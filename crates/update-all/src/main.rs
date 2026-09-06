fn main() {
    if let Some(code) = update_all::maybe_run_completion_query() {
        std::process::exit(code);
    }

    if let Err(err) = update_all::main_entry() {
        if let Some(exit) = err.downcast_ref::<update_all::CommonOperationExit>() {
            std::process::exit(exit.0);
        }
        if err.downcast_ref::<update_all::Cancelled>().is_some() {
            std::process::exit(3);
        }
        if err.downcast_ref::<update_all::InvalidPlan>().is_some() {
            update_all::ua_errln!("{err:#}");
            std::process::exit(3);
        }
        if err.downcast_ref::<update_all::Deferred>().is_some() {
            std::process::exit(2);
        }
        if err.downcast_ref::<update_all::IntegrityFailure>().is_some() {
            update_all::ua_errln!("{err:#}");
            std::process::exit(4);
        }
        update_all::ua_errln!("{err:#}");
        std::process::exit(1);
    }
}
