# ============================================================
#         PHISHING LINK DETECTOR — SHINY WEB APP
#         Save this as app.R in the same folder as
#         best_model_xgb.model
# ============================================================

# ── INSTALL & LOAD PACKAGES ──────────────────────────────────
packages <- c("shiny", "xgboost", "stringr")
install_if_missing <- function(pkg) {
  if (!requireNamespace(pkg, quietly = TRUE)) install.packages(pkg)
}
invisible(lapply(packages, install_if_missing))
invisible(lapply(packages, library, character.only = TRUE))


# ── LOAD MODEL ───────────────────────────────────────────────
model <- xgb.load("best_model_xgb.model")


# ── FEATURE EXTRACTION ───────────────────────────────────────
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
      str_detect(tolower(domain_part), kw))))
  url_has_login  <- as.integer(str_detect(tolower(url), "login"))
  url_has_verify <- as.integer(str_detect(tolower(url), "verify"))
  url_has_secure <- as.integer(str_detect(tolower(url), "secure"))
  url_has_update <- as.integer(str_detect(tolower(url), "update"))
  brand_in_domain <- as.integer(
    any(sapply(brands, function(b) str_detect(tolower(domain_part), b))) &
      !is_trusted_domain)
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
  query_str          <- str_extract(url, "\\?.*$")
  query_length       <- ifelse(is.na(query_str), 0, nchar(query_str))
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
    brand_in_domain, domain_length, subdomain_count, domain_hyphens,
    has_suspicious_tld, url_entropy, has_double_slash,
    digit_ratio, path_length, query_length,
    has_at_in_domain, has_encoding, domain_digit_ratio
  ))
}


# ── UI ───────────────────────────────────────────────────────
ui <- fluidPage(
  
  tags$head(
    tags$style(HTML("
      @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        background-color: #0a0e1a;
        color: #c8d6e5;
        font-family: 'Rajdhani', sans-serif;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .main-container {
        width: 100%;
        max-width: 680px;
        padding: 40px 20px;
      }

      .header {
        text-align: center;
        margin-bottom: 40px;
      }

      .header h1 {
        font-family: 'Share Tech Mono', monospace;
        font-size: 2.6em;
        color: #00d4ff;
        letter-spacing: 4px;
        text-shadow: 0 0 24px rgba(0,212,255,0.4);
        margin-bottom: 8px;
      }

      .header p {
        color: #4a6a85;
        font-size: 1em;
        letter-spacing: 2px;
        text-transform: uppercase;
      }

      .scan-box {
        background: #0f1629;
        border: 1px solid #1a2a4a;
        border-radius: 14px;
        padding: 32px;
        box-shadow: 0 8px 40px rgba(0,0,0,0.5);
      }

      .scan-box label {
        font-family: 'Share Tech Mono', monospace;
        color: #00d4ff;
        font-size: 0.8em;
        letter-spacing: 2px;
        display: block;
        margin-bottom: 10px;
      }

      #url_input {
        width: 100%;
        background: #060a14;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        color: #a8c8e8;
        font-family: 'Share Tech Mono', monospace;
        font-size: 1em;
        padding: 14px 16px;
        outline: none;
        transition: border-color 0.3s, box-shadow 0.3s;
      }

      #url_input:focus {
        border-color: #00d4ff;
        box-shadow: 0 0 14px rgba(0,212,255,0.15);
      }

      #scan_btn {
        width: 100%;
        margin-top: 16px;
        background: linear-gradient(135deg, #0066cc, #00a8ff);
        border: none;
        border-radius: 8px;
        color: white;
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.1em;
        font-weight: 700;
        letter-spacing: 3px;
        padding: 14px;
        cursor: pointer;
        transition: all 0.3s;
        text-transform: uppercase;
      }

      #scan_btn:hover {
        background: linear-gradient(135deg, #0077ee, #00c4ff);
        box-shadow: 0 4px 24px rgba(0,160,255,0.35);
        transform: translateY(-1px);
      }

      #scan_btn:active {
        transform: translateY(0px);
      }

      .result-wrapper {
        margin-top: 24px;
      }

      .result-box {
        border-radius: 12px;
        padding: 32px 24px;
        text-align: center;
        animation: fadeIn 0.4s ease;
      }

      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
      }

      .result-phishing {
        background: rgba(220, 38, 38, 0.08);
        border: 1px solid rgba(220, 38, 38, 0.35);
        box-shadow: 0 0 40px rgba(220,38,38,0.08);
      }

      .result-legitimate {
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.35);
        box-shadow: 0 0 40px rgba(16,185,129,0.08);
      }

      .result-icon {
        font-size: 3.2em;
        margin-bottom: 12px;
      }

      .result-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 2em;
        font-weight: 700;
        letter-spacing: 4px;
        margin-bottom: 10px;
      }

      .result-phishing  .result-label { color: #ef4444; }
      .result-legitimate .result-label { color: #10b981; }

      .result-confidence {
        font-size: 1.05em;
        color: #5a7a94;
        letter-spacing: 1px;
        margin-bottom: 14px;
      }

      .confidence-bar-wrap {
        background: #060a14;
        border-radius: 99px;
        height: 6px;
        width: 80%;
        margin: 0 auto 14px;
        overflow: hidden;
      }

      .confidence-bar-fill {
        height: 100%;
        border-radius: 99px;
        transition: width 0.6s ease;
      }

      .result-phishing  .confidence-bar-fill { background: #ef4444; }
      .result-legitimate .confidence-bar-fill { background: #10b981; }

      .result-url {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.75em;
        color: #2a4a65;
        word-break: break-all;
        margin-top: 4px;
      }

      .stats-row {
        display: flex;
        gap: 12px;
        margin-bottom: 24px;
      }

      .stat-card {
        flex: 1;
        background: #0f1629;
        border: 1px solid #1a2a4a;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      }

      .stat-number {
        font-family: 'Share Tech Mono', monospace;
        font-size: 1.8em;
        font-weight: 700;
      }

      .stat-total { color: #00d4ff; }
      .stat-phish { color: #ef4444; }
      .stat-legit { color: #10b981; }

      .stat-label {
        font-size: 0.8em;
        color: #3a5a75;
        letter-spacing: 1px;
        margin-top: 4px;
        text-transform: uppercase;
      }

      .footer {
        text-align: center;
        margin-top: 30px;
        color: #1e3a5f;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.75em;
        letter-spacing: 1px;
      }
    "))
  ),
  
  div(class = "main-container",
      
      # Header
      div(class = "header",
          h1("PHISHGUARD"),
          p("XGBoost · Phishing URL Detection")
      ),
      
      # Stats row
      div(class = "stats-row",
          div(class = "stat-card",
              div(class = "stat-number stat-total", textOutput("total_count")),
              div(class = "stat-label", "URLs Scanned")
          ),
          div(class = "stat-card",
              div(class = "stat-number stat-phish", textOutput("phish_count")),
              div(class = "stat-label", "Phishing Detected")
          ),
          div(class = "stat-card",
              div(class = "stat-number stat-legit", textOutput("legit_count")),
              div(class = "stat-label", "Legitimate")
          )
      ),
      
      # Scan box
      div(class = "scan-box",
          tags$label("ENTER URL TO SCAN"),
          tags$input(
            id          = "url_input",
            type        = "text",
            placeholder = "https://example.com"
          ),
          tags$button(
            id      = "scan_btn",
            "SCAN URL",
            onclick = "Shiny.setInputValue('scan_click', Math.random())"
          ),
          
          # Result appears inside scan box
          div(class = "result-wrapper",
              uiOutput("result_ui")
          )
      ),
      
      # Footer
      div(class = "footer",
          "Trained on 822,010 URLs · AUC 0.971"
      )
  )
)


# ── SERVER ───────────────────────────────────────────────────
server <- function(input, output, session) {
  
  observeEvent(input$scan_click, {
    url <- trimws(input$url_input)
    if (nchar(url) == 0) {
      output$result_ui <- renderUI({
        div(class = "result-box result-phishing", style = "margin-top:0;",
            div(class = "result-icon", "⚠️"),
            div(class = "result-label", style = "font-size:1.2em;", "PLEASE ENTER A URL")
        )
      })
      return()
    }
    
    tryCatch({
      features   <- extract_features(url)
      dmatrix    <- xgb.DMatrix(data = features)
      prob       <- predict(model, dmatrix)
      label      <- ifelse(prob >= 0.5, "LEGITIMATE", "PHISHING")
      confidence <- ifelse(prob >= 0.5, prob, 1 - prob) * 100
      css_class  <- ifelse(label == "PHISHING", "result-phishing", "result-legitimate")
      icon       <- ifelse(label == "PHISHING", "🚨", "✅")
      
      output$result_ui <- renderUI({
        div(class = paste("result-box", css_class),
            div(class = "result-icon", icon),
            div(class = "result-label", label),
            div(class = "result-confidence",
                sprintf("Confidence: %.1f%%", confidence)),
            div(class = "confidence-bar-wrap",
                div(class = "confidence-bar-fill",
                    style = sprintf("width: %.1f%%", confidence))),
            div(class = "result-url", url)
        )
      })
      
    }, error = function(e) {
      output$result_ui <- renderUI({
        div(class = "result-box result-phishing",
            div(class = "result-icon", "⚠️"),
            div(class = "result-label", style = "font-size:1.2em;", "INVALID URL"),
            div(class = "result-confidence", "Please enter a valid URL including http:// or https://")
        )
      })
    })
  })
  
  # Reactive counters
  total <- reactiveVal(0)
  phish <- reactiveVal(0)
  legit <- reactiveVal(0)
  
  observeEvent(input$scan_click, {
    url <- trimws(input$url_input)
    if (nchar(url) == 0) return()
    tryCatch({
      features <- extract_features(url)
      dmatrix  <- xgb.DMatrix(data = features)
      prob     <- predict(model, dmatrix)
      label    <- ifelse(prob >= 0.5, "LEGITIMATE", "PHISHING")
      total(total() + 1)
      if (label == "PHISHING") phish(phish() + 1) else legit(legit() + 1)
    }, error = function(e) {})
  }, priority = -1)
  
  output$total_count <- renderText({ total() })
  output$phish_count <- renderText({ phish() })
  output$legit_count <- renderText({ legit() })
  
  output$result_ui <- renderUI({ NULL })
}


# ── RUN ──────────────────────────────────────────────────────
shinyApp(ui = ui, server = server)