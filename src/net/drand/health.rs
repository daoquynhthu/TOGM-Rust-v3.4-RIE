use super::client::DrandClient;

pub fn check_health(client: &DrandClient) -> bool {
    // Try to fetch the latest beacon to verify connectivity
    client.get_latest().is_ok()
}
