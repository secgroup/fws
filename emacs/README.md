fws.el
=======

This directory provides an Emacs mode for editing
FWS queries.

## Usage

To use this mode:

1. Copy the file fws.el to a directory where Emacs will find it (that is, in your emacs load-path)
2. Add the following lines to your .emacs file:

```
(setq auto-mode-alist
	      (cons '("\\.fws" . fws-mode)  auto-mode-alist))
(autoload 'fws-mode "fws" "Major mode for editing FWS queries." t)
```
