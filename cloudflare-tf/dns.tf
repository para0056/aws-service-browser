resource "cloudflare_record" "site_cname" {
  zone_id = var.cloudflare_zone_id
  name    = "browser"
  value   = var.cloudfront_distribution_domain
  type    = "CNAME"
  proxied = true // routes through Cloudflare proxy
}
