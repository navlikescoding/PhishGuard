# ============================================================
#         PHISHING LINK DETECTION SYSTEM - R STUDIO
#         4 ML Models: RF, XGBoost, Logistic Reg, LiblineaR
#         v2 — Improved Feature Engineering
# ============================================================

# ── 1. INSTALL & LOAD PACKAGES ───────────────────────────────
packages <- c("tidyverse", "caret", "randomForest", "xgboost",
              "e1071", "glmnet", "stringr", "pROC", "tictoc", "LiblineaR")

install_if_missing <- function(pkg) {
  if (!requireNamespace(pkg, quietly = TRUE)) install.packages(pkg)
}
invisible(lapply(packages, install_if_missing))
invisible(lapply(packages, library, character.only = TRUE))

cat("✔ All packages loaded.\n")


# ── 2. IMPORT DATASET ────────────────────────────────────────
cat("Loading dataset...\n")

install.packages("data.table")
library(data.table)
df_raw <- as.data.frame(data.table::fread("D:/clg/pds/new_data_urls.csv"))

url_col   <- "url"
label_col <- "status"

cat(sprintf("✔ Dataset loaded: %d rows, %d columns.\n", nrow(df_raw), ncol(df_raw)))
cat(sprintf("   Phishing (0): %d | Legitimate (1): %d\n",
            sum(df_raw[[label_col]] == 0),
            sum(df_raw[[label_col]] == 1)))


# ── 3. FEATURE ENGINEERING (IMPROVED v2) ─────────────────────
cat("Extracting features...\n")

# Null coalescing helper
`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !is.na(a[1])) a else b

# Known trusted domain suffixes
trusted_domains <- c(
  "google.com", "youtube.com", "facebook.com", "twitter.com",
  "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
  "amazon.com", "wikipedia.org", "github.com", "stackoverflow.com",
  "reddit.com", "netflix.com", "spotify.com", "adobe.com",
  "dropbox.com", "zoom.us", "slack.com", "whatsapp.com",
  "vit.ac.in", ".ac.in", ".edu", ".gov", ".gov.in", ".nic.in"
)

# Suspicious keywords to check ONLY in domain (not path)
suspicious_keywords <- c("login", "signin", "verify", "secure", "account",
                         "update", "banking", "paypal", "ebay", "confirm",
                         "password", "credential", "authenticate")

# Brand names — flag if in domain but domain is not that brand
brands <- c("paypal", "ebay", "amazon", "google", "facebook",
            "microsoft", "apple", "netflix", "instagram", "twitter")

extract_features <- function(url) {
  url <- as.character(url)
  
  # Extract domain and path separately
  domain_part <- str_extract(url, "(?<=://)[^/]+")
  domain_part <- ifelse(is.na(domain_part), url, domain_part)
  domain_part <- str_replace(domain_part, ":\\d+$", "")  # remove port
  path_part   <- str_replace(url, "^[^/]+//[^/]+", "")
  
  # ── Basic URL structure ──────────────────────────────────────
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
  
  # ── Protocol ────────────────────────────────────────────────
  has_https          <- as.integer(str_detect(url, "^https://"))
  has_http           <- as.integer(str_detect(url, "^http://"))
  
  # ── IP address as domain ─────────────────────────────────────
  has_ip_address     <- as.integer(str_detect(domain_part,
                                              "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"))
  
  # ── Trusted domain check ──────────────────────────────────────
  is_trusted_domain  <- as.integer(any(str_detect(tolower(domain_part),
                                                  fixed(trusted_domains))))
  
  # ── Suspicious keywords in DOMAIN ONLY ───────────────────────
  domain_has_suspicious_keyword <- as.integer(
    any(sapply(suspicious_keywords, function(kw)
      str_detect(tolower(domain_part), kw)))
  )
  
  # ── Suspicious keywords in full URL (softer signals) ─────────
  url_has_login  <- as.integer(str_detect(tolower(url), "login"))
  url_has_verify <- as.integer(str_detect(tolower(url), "verify"))
  url_has_secure <- as.integer(str_detect(tolower(url), "secure"))
  url_has_update <- as.integer(str_detect(tolower(url), "update"))
  
  # ── Brand impersonation in domain ────────────────────────────
  brand_in_domain <- as.integer(
    any(sapply(brands, function(b) str_detect(tolower(domain_part), b))) &
      !is_trusted_domain
  )
  
  # ── Domain-level features ─────────────────────────────────────
  domain_length      <- nchar(domain_part)
  subdomain_count    <- max(str_count(domain_part, "\\.") - 1, 0)
  domain_hyphens     <- str_count(domain_part, "-")
  
  # ── Suspicious TLDs ──────────────────────────────────────────
  suspicious_tlds    <- c("\\.tk", "\\.ml", "\\.ga", "\\.cf", "\\.gq",
                          "\\.xyz", "\\.top", "\\.club", "\\.work",
                          "\\.online", "\\.site", "\\.click", "\\.link",
                          "\\.live", "\\.stream")
  has_suspicious_tld <- as.integer(any(str_detect(tolower(domain_part),
                                                  suspicious_tlds)))
  
  # ── URL entropy ───────────────────────────────────────────────
  char_freq  <- table(strsplit(url, "")[[1]])
  probs      <- char_freq / sum(char_freq)
  url_entropy <- -sum(probs * log2(probs + 1e-10))
  
  # ── Other structural signals ──────────────────────────────────
  has_double_slash  <- as.integer(str_count(url, "//") > 1)
  digit_ratio       <- num_digits / max(url_length, 1)
  path_length       <- nchar(path_part)
  
  query_str         <- str_extract(url, "\\?.*$")
  query_length      <- ifelse(is.na(query_str), 0, nchar(query_str))
  
  has_at_in_domain  <- as.integer(str_detect(domain_part, "@"))
  has_encoding      <- as.integer(str_detect(url, "%[0-9A-Fa-f]{2}"))
  domain_digit_ratio <- str_count(domain_part, "[0-9]") / max(domain_length, 1)
  
  data.frame(
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
  )
}

# Apply to all URLs
tic("Feature extraction")
features_list <- lapply(df_raw[[url_col]], extract_features)
features_df   <- bind_rows(features_list)
toc()

features_df$label <- as.factor(df_raw[[label_col]])

cat(sprintf("✔ Features extracted: %d features per URL.\n",
            ncol(features_df) - 1))


# ── 4. TRAIN / TEST SPLIT (70 / 30) ──────────────────────────
cat("Splitting dataset 70/30...\n")

set.seed(42)
train_idx  <- createDataPartition(features_df$label, p = 0.70, list = FALSE)
train_data <- features_df[ train_idx, ]
test_data  <- features_df[-train_idx, ]

cat(sprintf("✔ Train: %d rows | Test: %d rows\n",
            nrow(train_data), nrow(test_data)))

X_train <- train_data[, -ncol(train_data)]
y_train <- train_data$label
X_test  <- test_data[, -ncol(test_data)]
y_test  <- test_data$label


# ── 5. HELPER: EVALUATION FUNCTION ───────────────────────────
evaluate_model <- function(model_name, actual, predicted, predicted_prob = NULL) {
  cm <- confusionMatrix(predicted, actual, positive = "1")
  cat("\n", strrep("=", 55), "\n")
  cat(sprintf("  MODEL: %s\n", model_name))
  cat(strrep("=", 55), "\n")
  cat(sprintf("  Accuracy  : %.4f\n", cm$overall["Accuracy"]))
  cat(sprintf("  Precision : %.4f\n", cm$byClass["Precision"]))
  cat(sprintf("  Recall    : %.4f\n", cm$byClass["Recall"]))
  cat(sprintf("  F1 Score  : %.4f\n", cm$byClass["F1"]))
  if (!is.null(predicted_prob)) {
    roc_obj <- roc(as.numeric(as.character(actual)),
                   as.numeric(predicted_prob), quiet = TRUE)
    cat(sprintf("  AUC-ROC   : %.4f\n", auc(roc_obj)))
  }
  cat(strrep("=", 55), "\n")
  invisible(cm)
}


# ── 6. MODEL 1: LOGISTIC REGRESSION ──────────────────────────
cat("\n[1/4] Training Logistic Regression...\n")
tic()

lr_model <- glm(label ~ ., data = train_data, family = binomial())
lr_prob  <- predict(lr_model, newdata = X_test, type = "response")
lr_pred  <- factor(ifelse(lr_prob >= 0.5, "1", "0"), levels = levels(y_test))

toc()
evaluate_model("Logistic Regression", y_test, lr_pred, lr_prob)


# ── 7. MODEL 2: RANDOM FOREST ────────────────────────────────
cat("\n[2/4] Training Random Forest...\n")
tic()

rf_model <- randomForest(
  x          = X_train,
  y          = y_train,
  ntree      = 200,
  mtry       = floor(sqrt(ncol(X_train))),
  importance = TRUE,
  verbose    = FALSE
)

rf_pred <- predict(rf_model, newdata = X_test, type = "class")
rf_prob <- predict(rf_model, newdata = X_test, type = "prob")[, "1"]

toc()
evaluate_model("Random Forest", y_test, rf_pred, rf_prob)

cat("\nTop 10 Important Features (Random Forest):\n")
imp    <- importance(rf_model, type = 1)
imp_df <- data.frame(Feature = rownames(imp), Importance = imp[, 1])
imp_df <- imp_df[order(-imp_df$Importance), ]
print(head(imp_df, 10), row.names = FALSE)


# ── 8. MODEL 3: XGBOOST ──────────────────────────────────────
cat("\n[3/4] Training XGBoost...\n")
tic()

X_train_mat <- as.matrix(X_train)
X_test_mat  <- as.matrix(X_test)
y_train_num <- as.numeric(as.character(y_train))
y_test_num  <- as.numeric(as.character(y_test))

dtrain <- xgb.DMatrix(data = X_train_mat, label = y_train_num)
dtest  <- xgb.DMatrix(data = X_test_mat,  label = y_test_num)

xgb_params <- list(
  objective        = "binary:logistic",
  eval_metric      = "auc",
  eta              = 0.1,
  max_depth        = 6,
  subsample        = 0.8,
  colsample_bytree = 0.8,
  min_child_weight = 5,
  nthread          = parallel::detectCores() - 1
)

xgb_model <- xgb.train(
  params                = xgb_params,
  data                  = dtrain,
  nrounds               = 150,
  watchlist             = list(train = dtrain, test = dtest),
  verbose               = 0,
  early_stopping_rounds = 15
)

xgb_prob <- predict(xgb_model, dtest)
xgb_pred <- factor(ifelse(xgb_prob >= 0.5, "1", "0"), levels = levels(y_test))

toc()
evaluate_model("XGBoost", y_test, xgb_pred, xgb_prob)

cat("\nTop 10 Important Features (XGBoost):\n")
xgb_imp <- xgb.importance(model = xgb_model)
print(head(xgb_imp[, c("Feature", "Gain")], 10))


# ── 9. MODEL 4: LiblineaR ────────────────────────────────────
cat("\n[4/4] Training LiblineaR (Fast Linear SVM)...\n")
tic()

pre_proc    <- preProcess(X_train, method = c("center", "scale"))
X_train_svm <- as.matrix(predict(pre_proc, X_train))
X_test_svm  <- as.matrix(predict(pre_proc, X_test))

liblinear_model <- LiblineaR(
  data    = X_train_svm,
  target  = as.numeric(as.character(y_train)),
  type    = 7,
  cost    = 0.1,
  verbose = FALSE
)

liblinear_pred_raw <- predict(liblinear_model, X_test_svm, proba = TRUE)
svm_pred <- factor(as.character(liblinear_pred_raw$predictions), levels = levels(y_test))
svm_prob <- liblinear_pred_raw$probabilities[, "1"]

toc()
evaluate_model("LiblineaR (Linear SVM)", y_test, svm_pred, svm_prob)


# ── 10. SUMMARY COMPARISON TABLE ─────────────────────────────
cat("\n\n", strrep("*", 60), "\n")
cat("               FINAL MODEL COMPARISON\n")
cat(strrep("*", 60), "\n")

get_metrics <- function(actual, predicted, prob) {
  cm      <- confusionMatrix(predicted, actual, positive = "1")
  roc_obj <- roc(as.numeric(as.character(actual)),
                 as.numeric(prob), quiet = TRUE)
  list(
    Accuracy  = round(cm$overall["Accuracy"],  4),
    Precision = round(cm$byClass["Precision"], 4),
    Recall    = round(cm$byClass["Recall"],    4),
    F1        = round(cm$byClass["F1"],        4),
    AUC       = round(auc(roc_obj),            4)
  )
}

results <- rbind(
  data.frame(Model = "Logistic Regression", get_metrics(y_test, lr_pred,  lr_prob)),
  data.frame(Model = "Random Forest",       get_metrics(y_test, rf_pred,  rf_prob)),
  data.frame(Model = "XGBoost",             get_metrics(y_test, xgb_pred, xgb_prob)),
  data.frame(Model = "LiblineaR",           get_metrics(y_test, svm_pred, svm_prob))
)

rownames(results) <- NULL
print(results)

cat("\n✔ Done! Best model by AUC:",
    results$Model[which.max(results$AUC)], "\n")

# ── 12. GRAPHS & CONFUSION MATRICES ──────────────────────────

# Install ggplot2 if needed
if (!requireNamespace("ggplot2", quietly = TRUE)) install.packages("ggplot2")
library(ggplot2)

# ── Confusion Matrix plots ────────────────────────────────────
plot_confusion_matrix <- function(actual, predicted, model_name) {
  cm     <- confusionMatrix(predicted, actual, positive = "1")
  cm_df  <- as.data.frame(cm$table)
  colnames(cm_df) <- c("Predicted", "Actual", "Freq")
  
  ggplot(cm_df, aes(x = Actual, y = Predicted, fill = Freq)) +
    geom_tile(color = "white") +
    geom_text(aes(label = Freq), size = 6, fontface = "bold") +
    scale_fill_gradient(low = "white", high = "steelblue") +
    labs(title = paste("Confusion Matrix —", model_name),
         x = "Actual", y = "Predicted") +
    theme_minimal(base_size = 14)
}

print(plot_confusion_matrix(y_test, lr_pred,  "Logistic Regression"))
print(plot_confusion_matrix(y_test, rf_pred,  "Random Forest"))
print(plot_confusion_matrix(y_test, xgb_pred, "XGBoost"))
print(plot_confusion_matrix(y_test, svm_pred, "LiblineaR"))


# ── ROC Curves (all 4 models on one plot) ────────────────────
roc_lr  <- roc(as.numeric(as.character(y_test)), as.numeric(lr_prob),  quiet = TRUE)
roc_rf  <- roc(as.numeric(as.character(y_test)), as.numeric(rf_prob),  quiet = TRUE)
roc_xgb <- roc(as.numeric(as.character(y_test)), as.numeric(xgb_prob), quiet = TRUE)
roc_svm <- roc(as.numeric(as.character(y_test)), as.numeric(svm_prob), quiet = TRUE)

roc_df <- rbind(
  data.frame(FPR = 1 - roc_lr$specificities,  TPR = roc_lr$sensitivities,
             Model = sprintf("Logistic Reg (AUC=%.3f)", auc(roc_lr))),
  data.frame(FPR = 1 - roc_rf$specificities,  TPR = roc_rf$sensitivities,
             Model = sprintf("Random Forest (AUC=%.3f)", auc(roc_rf))),
  data.frame(FPR = 1 - roc_xgb$specificities, TPR = roc_xgb$sensitivities,
             Model = sprintf("XGBoost (AUC=%.3f)", auc(roc_xgb))),
  data.frame(FPR = 1 - roc_svm$specificities, TPR = roc_svm$sensitivities,
             Model = sprintf("LiblineaR (AUC=%.3f)", auc(roc_svm)))
)

print(
  ggplot(roc_df, aes(x = FPR, y = TPR, color = Model)) +
    geom_line(size = 1.2) +
    geom_abline(linetype = "dashed", color = "gray") +
    labs(title = "ROC Curves — All Models",
         x = "False Positive Rate", y = "True Positive Rate") +
    theme_minimal(base_size = 14) +
    theme(legend.position = "bottom")
)


# ── Model Comparison Bar Chart ────────────────────────────────
results_long <- tidyr::pivot_longer(results,
                                    cols = c(Accuracy, Precision, Recall, F1, AUC),
                                    names_to = "Metric", values_to = "Value")

print(
  ggplot(results_long, aes(x = Model, y = Value, fill = Model)) +
    geom_bar(stat = "identity") +
    facet_wrap(~ Metric, scales = "free_y") +
    labs(title = "Model Performance Comparison", x = "", y = "Score") +
    theme_minimal(base_size = 12) +
    theme(axis.text.x = element_blank(),
          legend.position = "bottom")
)


# ── Feature Importance Plot (XGBoost) ─────────────────────────
xgb_imp_df <- as.data.frame(xgb.importance(model = xgb_model))
xgb_imp_top <- head(xgb_imp_df, 15)

print(
  ggplot(xgb_imp_top, aes(x = reorder(Feature, Gain), y = Gain, fill = Gain)) +
    geom_bar(stat = "identity") +
    coord_flip() +
    scale_fill_gradient(low = "lightblue", high = "steelblue") +
    labs(title = "Top 15 Feature Importances (XGBoost)",
         x = "Feature", y = "Gain") +
    theme_minimal(base_size = 13)
)


# ── 11. SAVE BEST MODEL ───────────────────────────────────────
best_model_name <- results$Model[which.max(results$AUC)]

if (best_model_name == "XGBoost") {
  xgb.save(xgb_model, "best_model_xgb.model")
  cat("✔ XGBoost model saved as 'best_model_xgb.model'\n")
} else if (best_model_name == "Random Forest") {
  saveRDS(rf_model, "best_model_rf.rds")
  cat("✔ Random Forest model saved as 'best_model_rf.rds'\n")
} else if (best_model_name == "Logistic Regression") {
  saveRDS(lr_model, "best_model_lr.rds")
  cat("✔ Logistic Regression model saved as 'best_model_lr.rds'\n")
} else {
  saveRDS(liblinear_model, "best_model_liblinear.rds")
  cat("✔ LiblineaR model saved as 'best_model_liblinear.rds'\n")
}

# ── END ───────────────────────────────────────────────────────