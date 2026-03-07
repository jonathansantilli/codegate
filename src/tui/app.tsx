import { render } from "ink";
import type { CodeGateReport } from "../types/report.js";
import { DashboardView } from "./views/dashboard.js";
import { ProgressView } from "./views/progress.js";
import { SummaryView } from "./views/summary.js";

export type TuiView = "dashboard" | "progress" | "summary";

export interface CodeGateTuiAppProps {
  view: TuiView;
  report?: CodeGateReport;
  progressMessage?: string;
  notices?: string[];
}

export function CodeGateTuiApp(props: CodeGateTuiAppProps) {
  if (props.view === "progress") {
    return <ProgressView progressMessage={props.progressMessage} />;
  }

  if (!props.report) {
    return <ProgressView progressMessage="Preparing report..." />;
  }

  if (props.view === "summary") {
    return <SummaryView report={props.report} />;
  }

  return <DashboardView report={props.report} notices={props.notices} />;
}

export function renderTuiApp(props: CodeGateTuiAppProps): void {
  const app = render(<CodeGateTuiApp {...props} />);
  app.unmount();
}
