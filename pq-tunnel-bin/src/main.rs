//! Thin CLI wrapper over the `pq_tunnel_lib` library (all logic lives in the
//! library so integration tests can drive it).

fn main() {
    if let Err(e) = pq_tunnel_lib::main_entry() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
