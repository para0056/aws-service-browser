provider "cloudflare" {
  email     = var.cloudflare_email    // your Cloudflare account email
  api_token = var.cloudflare_api_token // scoped token with DNS and Access write
}