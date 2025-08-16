resource "cloudflare_access_application" "service_browser" {
  zone_id          = var.cloudflare_zone_id
  name             = "Service Browser"
  type             = "self_hosted"
  domain           = "browser.example.com" // your public hostname
  session_duration = "24h"
}
