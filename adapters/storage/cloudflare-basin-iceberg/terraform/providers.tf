provider "cloudflare" {
  api_token = var.cloudflare_api_token
  base_url  = var.cloudflare_api_base_url
}

provider "restful" {
  base_url = var.cloudflare_api_base_url

  security = {
    http = {
      token = {
        token = var.cloudflare_api_token
      }
    }
  }
}
