package livetest

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// writeReport prints the config file the baseline case loaded, if it ran,
// and one row per case and URL.
func writeReport(
	w io.Writer,
	baseline *logStats,
	results []result,
	outDir string,
) error {
	if baseline != nil {
		if _, err := fmt.Fprintf(
			w,
			"baseline config: %s\n\n",
			baselineConfig(*baseline),
		); err != nil {
			return err
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CASE\tURL\tOK\tOUTCOMES\tWARN\tERR")
	for _, r := range results {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%d\t%d\n",
			r.caseLabel, r.url, r.ok, r.tries, r.summary(), r.warns, r.errs)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if outDir == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "\nlogs: %s/<case>.log\n", outDir)
	return err
}

func baselineConfig(stats logStats) string {
	switch {
	case !stats.configKnown:
		return "unknown (not in the log)"
	case stats.config == "":
		return "none (defaults)"
	default:
		return stats.config
	}
}
