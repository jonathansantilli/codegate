export interface TuiTheme {
  title: string;
  ok: string;
  warning: string;
  danger: string;
  muted: string;
}

export const defaultTheme: TuiTheme = {
  title: "cyan",
  ok: "green",
  warning: "yellow",
  danger: "red",
  muted: "gray",
};
