fn main() {
    if let Err(err) = update_all::main_entry() {
        if err.downcast_ref::<update_all::Cancelled>().is_some() {
            std::process::exit(130);
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
