use crate::{Cleanup, LeaseLifecycle, LeaseLimits, LeaseState, SessionError, StopReason};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::time::Duration;

/// Product-owned native scope or permission constraint. The product constructs
/// scope values from retained OS evidence, never from untrusted selectors.
pub trait Constraint {
    fn contains(&self, narrower: &Self) -> bool;
}

/// An observation/lookup key, not a capability. Trusted issuers choose unique IDs.
pub type GrantId = u128;

struct Record<S, A> {
    scope: S,
    authority: A,
    lifetime: LeaseLifecycle,
    parent: Option<GrantId>,
}

pub struct GrantView<'a, S, A> {
    pub id: GrantId,
    pub scope: &'a S,
    pub authority: &'a A,
    pub lifetime: &'a LeaseLifecycle,
    pub parent: Option<GrantId>,
}

/// A single trusted coordinator owns mutations. This registry neither obtains
/// approval nor claims cleanup; the product retains and terminates native work.
pub struct GrantRegistry<S, A> {
    records: BTreeMap<GrantId, Record<S, A>>,
    capacity: usize,
}

impl<S: Constraint, A: Constraint> GrantRegistry<S, A> {
    pub fn new(capacity: usize) -> Result<Self, SessionError> {
        if capacity == 0 {
            return Err(SessionError::Capacity);
        }
        Ok(Self {
            records: BTreeMap::new(),
            capacity,
        })
    }

    /// Issue only after the product obtains native approval and prepares the
    /// owned execution boundary. IDs and scope values do not authorize issuance.
    pub fn issue(
        &mut self,
        id: GrantId,
        scope: S,
        authority: A,
        limits: LeaseLimits,
        uses: Option<NonZeroU64>,
        now: Duration,
    ) -> Result<(), SessionError> {
        self.require_free_id(id)?;
        let lifetime = LeaseLifecycle::with_use_limit(limits, now, uses)?;
        self.records.insert(
            id,
            Record {
                scope,
                authority,
                lifetime,
                parent: None,
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &mut self,
        parent: GrantId,
        caller: &S,
        id: GrantId,
        scope: S,
        authority: A,
        limits: LeaseLimits,
        uses: Option<NonZeroU64>,
        now: Duration,
    ) -> Result<(), SessionError> {
        self.poll(now);
        self.require_free_id(id)?;
        let lifetime = LeaseLifecycle::with_use_limit(limits, now, uses)?;
        let source = self
            .records
            .get_mut(&parent)
            .ok_or(SessionError::UnknownGrant)?;
        if !source.scope.contains(caller) {
            return Err(SessionError::IdentityMismatch);
        }
        if !source.scope.contains(&scope)
            || !source.authority.contains(&authority)
            || lifetime.hard_deadline() > source.lifetime.hard_deadline()
            || limits.idle_timeout() > source.lifetime.limits().idle_timeout()
        {
            return Err(SessionError::AuthorityWidened);
        }
        source.lifetime.reserve_uses(now, uses)?;
        self.records.insert(
            id,
            Record {
                scope,
                authority,
                lifetime,
                parent: Some(parent),
            },
        );
        Ok(())
    }

    /// Check one explicitly selected grant. A failure never searches a broader
    /// grant. Failed execution after admission does not refund the use allowance.
    pub fn admit(
        &mut self,
        id: GrantId,
        caller: &S,
        operation: &A,
        now: Duration,
    ) -> Result<(), SessionError> {
        self.poll(now);
        let grant = self.records.get(&id).ok_or(SessionError::UnknownGrant)?;
        if !grant.scope.contains(caller) {
            return Err(SessionError::IdentityMismatch);
        }
        if !grant.authority.contains(operation) {
            return Err(SessionError::AuthorityWidened);
        }
        let ancestors = self.ancestors(id)?;
        self.records
            .get_mut(&id)
            .ok_or(SessionError::UnknownGrant)?
            .lifetime
            .admit(now)?;
        // Actual delegated execution is useful activity for its parent grant;
        // creating/inspecting a delegation never reaches this path.
        for parent in ancestors {
            self.records
                .get_mut(&parent)
                .ok_or(SessionError::UnknownGrant)?
                .lifetime
                .record_activity(now)?;
        }
        Ok(())
    }

    /// Expiry and parent loss become denial before native cleanup starts.
    pub fn poll(&mut self, now: Duration) {
        for record in self.records.values_mut() {
            record.lifetime.poll(now);
        }
        let mut stopped: BTreeSet<GrantId> = self
            .records
            .iter()
            .filter_map(|(id, record)| {
                (record.lifetime.state() != LeaseState::Active).then_some(*id)
            })
            .collect();
        loop {
            let mut changed = false;
            for (id, record) in &mut self.records {
                if record
                    .parent
                    .is_some_and(|parent| stopped.contains(&parent))
                    && stopped.insert(*id)
                {
                    record.lifetime.stop(StopReason::ParentRevoked);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Caller authorization for administrative revocation remains product-owned.
    pub fn stop(
        &mut self,
        id: GrantId,
        reason: StopReason,
        now: Duration,
    ) -> Result<(), SessionError> {
        self.records
            .get_mut(&id)
            .ok_or(SessionError::UnknownGrant)?
            .lifetime
            .stop(reason);
        self.poll(now);
        Ok(())
    }

    pub fn stop_all(&mut self, reason: StopReason, now: Duration) {
        for record in self.records.values_mut() {
            record.lifetime.stop(reason);
        }
        self.poll(now);
    }

    pub fn report_cleanup(&mut self, id: GrantId, cleanup: Cleanup) -> Result<(), SessionError> {
        if cleanup == Cleanup::Complete
            && self
                .records
                .values()
                .any(|record| record.parent == Some(id) && !record.lifetime.state().is_terminal())
        {
            return Err(SessionError::InvalidTransition);
        }
        self.records
            .get_mut(&id)
            .ok_or(SessionError::UnknownGrant)?
            .lifetime
            .report_cleanup(cleanup)
    }

    pub fn get(&self, id: GrantId) -> Option<GrantView<'_, S, A>> {
        self.records.get(&id).map(|record| Self::view(id, record))
    }

    pub fn iter(&self) -> impl Iterator<Item = GrantView<'_, S, A>> {
        self.records
            .iter()
            .map(|(id, record)| Self::view(*id, record))
    }

    /// Remove observations only after native cleanup and child retirement. Never
    /// remove a live grant merely to free capacity or make its ID reusable.
    pub fn retire(&mut self, id: GrantId) -> Result<(), SessionError> {
        let grant = self.records.get(&id).ok_or(SessionError::UnknownGrant)?;
        if !grant.lifetime.state().is_terminal()
            || self
                .records
                .values()
                .any(|record| record.parent == Some(id))
        {
            return Err(SessionError::InvalidTransition);
        }
        self.records.remove(&id);
        Ok(())
    }

    fn view(id: GrantId, record: &Record<S, A>) -> GrantView<'_, S, A> {
        GrantView {
            id,
            scope: &record.scope,
            authority: &record.authority,
            lifetime: &record.lifetime,
            parent: record.parent,
        }
    }

    fn require_free_id(&self, id: GrantId) -> Result<(), SessionError> {
        if self.records.contains_key(&id) {
            return Err(SessionError::DuplicateGrant);
        }
        if self.records.len() >= self.capacity {
            return Err(SessionError::Capacity);
        }
        Ok(())
    }

    fn ancestors(&self, mut id: GrantId) -> Result<Vec<GrantId>, SessionError> {
        let mut parents = Vec::new();
        while let Some(parent) = self
            .records
            .get(&id)
            .ok_or(SessionError::UnknownGrant)?
            .parent
        {
            parents.push(parent);
            id = parent;
        }
        Ok(parents)
    }
}
