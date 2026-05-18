// Application-wide configuration

export const config = {
  apiUrl:
    import.meta.env.VITE_API_URL ||
    (import.meta.env.MODE === "test" ? "http://localhost" : ""),
  wsUrl:
    import.meta.env.VITE_WS_URL ||
    (import.meta.env.MODE === "test" ? "ws://localhost" : ""),
};

export default config;
