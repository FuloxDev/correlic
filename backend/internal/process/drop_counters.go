package process

import "expvar"

// Exit drop counters, exported via /debug/vars. No logs; use for drop stats and debugging "missing exits".
var (
	ExecExitFuture          = expvar.NewInt("exec_exit_future")             // exit timestamp > max event time + window
	ExecExitBeforeExec      = expvar.NewInt("exec_exit_before_exec")        // exit timestamp before exec start
	ExecExitNoExec          = expvar.NewInt("exec_exit_no_exec")            // exit with no matching process_exec in set
	ExecExitYearOutOfBounds = expvar.NewInt("exec_exit_year_out_of_bounds") // exit timestamp year outside configured range (clock skew)
)
