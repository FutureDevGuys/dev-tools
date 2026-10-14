//! The deployment parser owns binding selections; source proposals use that
//! same closed authority type rather than another deployment schema model.
pub use crate::deployment::DeploymentBinding;
use anyhow::{bail, Result};
pub type BindingDeploymentDocument = crate::deployment::DeploymentDocument;

pub fn parse(bytes: &[u8]) -> Result<BindingDeploymentDocument> {
    let document = crate::deployment::parse_deployment_document(bytes)?;
    if document.schema != "dev-auth-deployment-v3"
        || document.purpose != crate::deployment::SetupPurpose::Credentials
    {
        bail!("binding source selection requires an explicit credential-purpose deployment V3");
    }
    Ok(document)
}
