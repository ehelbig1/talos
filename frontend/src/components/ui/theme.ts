/**
 * Shared style objects for the dark UI theme.
 * Used to replace duplicated inline style literals across components.
 */
export const darkSurface = {
  background: "#1A1D27",
  color: "#F8FAFC",
};

export const darkerSurface = {
  background: "#0F1117",
  color: "#F8FAFC",
};

export const darkButton = {
  background: "#252836",
  color: "#F8FAFC",
  border: "1px solid rgba(255,255,255,0.12)",
  borderRadius: "4px",
};

/**
 * Shared style for informational note boxes used throughout the builder UI.
 */
export const noteBoxStyle = {
  background: "rgba(99, 102, 241, 0.1)", // subtle primary/violet tint
  color: "#818CF8",
  border: "1px solid rgba(99, 102, 241, 0.2)",
};

/** Shared input field styling */
export const inputStyle = {
  width: "100%",
  padding: "0.5rem",
  border: "1px solid rgba(255,255,255,0.12)",
  borderRadius: "6px",
  backgroundColor: "#0F1117",
  color: "#F8FAFC",
};

/** Shared label styling */
export const labelStyle = {
  display: "block",
  fontWeight: "500",
  color: "#94A3B8", // muted-foreground
};

/** Card container styling used in dialogs */
export const cardStyle = {
  background: "#1A1D27",
  borderRadius: "8px",
  padding: "1rem",
  border: "1px solid rgba(255,255,255,0.08)",
  boxShadow: "0 4px 6px -1px rgba(0,0,0,0.3)",
};

/**
 * Style for the selectable template cards used in the "Create Module" dialog.
 */
export const templateCardStyle = {
  background: "#1A1D27",
  border: "1px solid rgba(255,255,255,0.12)",
  borderRadius: "10px",
  padding: "16px",
  cursor: "pointer",
  transition: "all 0.2s",
  color: "#F8FAFC",
};

/**
 * Generic panel container used by many builder dialogs.
 */
export const panelStyle = {
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: "8px",
  padding: "1rem",
  marginBottom: "1rem",
  background: "rgba(255,255,255,0.02)",
};

/** Simple gray border used in several list items */
export const grayBorderStyle = {
  border: "1px solid rgba(255,255,255,0.08)",
};

/** Reusable thin bottom border used in tables and separators */
export const thinBottomBorder = {
  borderBottom: "1px solid rgba(255,255,255,0.08)",
};

/** Simple vertical scroll wrapper */
export const scrollableStyle = {
  overflowY: "auto",
};

/**
 * Small parameter item style within the ManualEndpointCreator.
 */
export const parameterItemStyle = {
  display: "flex",
  gap: "0.5rem",
  padding: "0.5rem",
  background: "rgba(255,255,255,0.03)",
  border: "1px solid rgba(255,255,255,0.05)",
  borderRadius: "4px",
  alignItems: "center",
};
