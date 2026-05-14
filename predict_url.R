# ============================================================
#         PHISHING LINK DETECTOR — PREDICTION SCRIPT v2
#         Uses saved XGBoost model to classify any URL
# ============================================================

# ── 1. LOAD PACKAGES ─────────────────────────────────────────
library(xgboost)
library(stringr)

cat("✔ Packages loaded.\n")


# ── 2. LOAD SAVED MODEL ──────────────────────────────────────
model <- xgb.load("D:/clg/pds/best_model_xgb.model")
cat("✔ XGBoost model loaded.\n\n")


# ── 3. FEATURE EXTRACTION (must match training v2) ───────────
`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !is.na(a[1])) a else b

trusted_domains <- c(
  "google.com", "youtube.com", "facebook.com", "twitter.com",
  "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
  "amazon.com", "wikipedia.org", "github.com", "stackoverflow.com",
  "reddit.com", "netflix.com", "spotify.com", "adobe.com",
  "dropbox.com", "zoom.us", "slack.com", "whatsapp.com",
  "vit.ac.in", ".ac.in", ".edu", ".gov", ".gov.in", ".nic.in"
)

suspicious_keywords <- c("login", "signin", "verify", "secure", "account",
                         "update", "banking", "paypal", "ebay", "confirm",
                         "password", "credential", "authenticate")

brands <- c("paypal", "ebay", "amazon", "google", "facebook",
            "microsoft", "apple", "netflix", "instagram", "twitter")

extract_features <- function(url) {
  url <- as.character(url)
  
  domain_part <- str_extract(url, "(?<=://)[^/]+")
  domain_part <- ifelse(is.na(domain_part), url, domain_part)
  domain_part <- str_replace(domain_part, ":\\d+$", "")
  path_part   <- str_replace(url, "^[^/]+//[^/]+", "")
  
  url_length         <- nchar(url)
  num_dots           <- str_count(url, "\\.")
  num_hyphens        <- str_count(url, "-")
  num_underscores    <- str_count(url, "_")
  num_slashes        <- str_count(url, "/")
  num_at             <- str_count(url, "@")
  num_question_marks <- str_count(url, "\\?")
  num_equals         <- str_count(url, "=")
  num_ampersands     <- str_count(url, "&")
  num_digits         <- str_count(url, "[0-9]")
  num_special_chars  <- str_count(url, "[^a-zA-Z0-9]")
  
  has_https          <- as.integer(str_detect(url, "^https://"))
  has_http           <- as.integer(str_detect(url, "^http://"))
  has_ip_address     <- as.integer(str_detect(domain_part,
                                              "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"))
  
  is_trusted_domain  <- as.integer(any(str_detect(tolower(domain_part),
                                                  fixed(trusted_domains))))
  
  domain_has_suspicious_keyword <- as.integer(
    any(sapply(suspicious_keywords, function(kw)
      str_detect(tolower(domain_part), kw)))
  )
  
  url_has_login  <- as.integer(str_detect(tolower(url), "login"))
  url_has_verify <- as.integer(str_detect(tolower(url), "verify"))
  url_has_secure <- as.integer(str_detect(tolower(url), "secure"))
  url_has_update <- as.integer(str_detect(tolower(url), "update"))
  
  brand_in_domain <- as.integer(
    any(sapply(brands, function(b) str_detect(tolower(domain_part), b))) &
      !is_trusted_domain
  )
  
  domain_length      <- nchar(domain_part)
  subdomain_count    <- max(str_count(domain_part, "\\.") - 1, 0)
  domain_hyphens     <- str_count(domain_part, "-")
  
  suspicious_tlds    <- c("\\.tk", "\\.ml", "\\.ga", "\\.cf", "\\.gq",
                          "\\.xyz", "\\.top", "\\.club", "\\.work",
                          "\\.online", "\\.site", "\\.click", "\\.link",
                          "\\.live", "\\.stream")
  has_suspicious_tld <- as.integer(any(str_detect(tolower(domain_part),
                                                  suspicious_tlds)))
  
  char_freq   <- table(strsplit(url, "")[[1]])
  probs       <- char_freq / sum(char_freq)
  url_entropy <- -sum(probs * log2(probs + 1e-10))
  
  has_double_slash   <- as.integer(str_count(url, "//") > 1)
  digit_ratio        <- num_digits / max(url_length, 1)
  path_length        <- nchar(path_part)
  
  query_str    <- str_extract(url, "\\?.*$")
  query_length <- ifelse(is.na(query_str), 0, nchar(query_str))
  
  has_at_in_domain   <- as.integer(str_detect(domain_part, "@"))
  has_encoding       <- as.integer(str_detect(url, "%[0-9A-Fa-f]{2}"))
  domain_digit_ratio <- str_count(domain_part, "[0-9]") / max(domain_length, 1)
  
  as.matrix(data.frame(
    url_length, num_dots, num_hyphens, num_underscores,
    num_slashes, num_at, num_question_marks, num_equals,
    num_ampersands, num_digits, num_special_chars,
    has_https, has_http, has_ip_address,
    is_trusted_domain, domain_has_suspicious_keyword,
    url_has_login, url_has_verify, url_has_secure, url_has_update,
    brand_in_domain,
    domain_length, subdomain_count, domain_hyphens,
    has_suspicious_tld, url_entropy, has_double_slash,
    digit_ratio, path_length, query_length,
    has_at_in_domain, has_encoding, domain_digit_ratio
  ))
}


# ── 4. PREDICTION FUNCTION ───────────────────────────────────
predict_url <- function(url) {
  features   <- extract_features(url)
  dmatrix    <- xgb.DMatrix(data = features)
  prob       <- predict(model, dmatrix)
  label      <- ifelse(prob >= 0.5, "LEGITIMATE", "PHISHING")
  confidence <- ifelse(prob >= 0.5, prob, 1 - prob) * 100
  
  cat("\n", strrep("-", 55), "\n")
  cat(sprintf("  URL       : %s\n", url))
  if (label == "PHISHING") {
    cat("  Result    : PHISHING\n")
  } else {
    cat("  Result    : LEGITIMATE\n")
  }
  cat(sprintf("  Confidence: %.1f%%\n", confidence))
  cat(strrep("-", 55), "\n")
}


# ── 5. INTERACTIVE LOOP ──────────────────────────────────────
cat("============================================================\n")
cat("        PHISHING LINK DETECTOR v2 — Ready to scan\n")
cat("        Type a URL and press Enter to classify it.\n")
cat("        Type 'quit' to exit.\n")
cat("============================================================\n")

repeat {
  cat("\nEnter URL: ")
  input <- readLines(con = stdin(), n = 1)
  input <- trimws(input)
  
  if (tolower(input) == "quit") {
    cat("\n✔ Exiting detector. Goodbye!\n")
    break
  }
  
  if (nchar(input) == 0) {
    cat("Please enter a valid URL.\n")
    next
  }
  
  tryCatch(
    predict_url(input),
    error = function(e) cat("Error processing URL:", conditionMessage(e), "\n")
  )
}

# ── END ───────────────────────────────────────────────────────