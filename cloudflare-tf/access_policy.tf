resource "cloudflare_access_policy" "allow_team_members" {
  application_id = cloudflare_access_application.service_browser.id
  zone_id        = var.cloudflare_zone_id
  name           = "Allow Team"
  precedence     = 1
  decision       = "allow"

  include {
    email {
      emails = [
        "alice@company.com",
        "bob@company.com"
      ]
    }
  }

  require {
    any {
      one_time_pin = true
    }
  }
}
