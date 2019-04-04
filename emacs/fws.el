
(defvar fws-kw
  '("echo" "load_policy" "table_style" "help" "show_time" "verbose_mode" "aliases"
    "synthesis" "ifcl" "equivalence" "implication" "diff" "related" "nondet"
    "where" "in" "project" "filter" "forward" "input" "output" "nat" "all" "and" "or" "not"
    "NEW" "ESTABLISHED")
  "FWS Keywords")

(defvar fws-kw-regexp (regexp-opt fws-kw 'words))

(setq fws-keywords
      `((,fws-kw-regexp . font-lock-keyword-face)))

(define-derived-mode fws-mode fundamental-mode
  (setq font-lock-defaults '(fws-keywords))
  (setq mode-name "FWS")

  ;; python style comments
  (modify-syntax-entry ?# "<" fws-mode-syntax-table)
  (modify-syntax-entry ?\n ">" fws-mode-syntax-table)
  
  ;; ' belongs to ordinary identifiers
  (modify-syntax-entry ?' "w" fws-mode-syntax-table))
