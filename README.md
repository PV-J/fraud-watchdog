##
The UPI fraud system provides a hard result (money stolen) with a soft solution (probabilistic scoring). This is architecturally incoherent. A PLC never allows a hard fault with a soft response. fraud-watchdog is a deterministic temporal interlock for payments — no ML, no black box.
##