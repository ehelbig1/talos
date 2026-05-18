import React from "react";
import { render, screen, fireEvent, waitFor } from "../../test-utils";
import { GoogleCalendarSelector } from "./GoogleCalendarSelector";
import { server } from "../../../vitest.setup";
import { http, HttpResponse } from "msw";
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("GoogleCalendarSelector", () => {
  const mockOnSelect = vi.fn();

  const mockIntegrations = [
    {
      id: "int-1",
      email: "test@example.com",
      created_at: new Date().toISOString(),
    },
  ];

  const mockCalendars = [
    {
      id: "cal-1",
      summary: "Work Calendar",
      primary: true,
    },
    {
      id: "cal-2",
      summary: "Personal Calendar",
      description: "Personal events",
    },
  ];

  beforeEach(() => {
    mockOnSelect.mockClear();
    server.use(
      http.get("/api/google-calendar/integrations", () => {
        return HttpResponse.json({
          success: true,
          data: mockIntegrations,
        });
      }),
    );
  });

  it("renders loading state initially", async () => {
    render(<GoogleCalendarSelector onSelect={mockOnSelect} />);
    expect(
      screen.getByText(/Loading Google Calendar integrations/i),
    ).toBeInTheDocument();
  });

  it("renders integrations and allows selection", async () => {
    server.use(
      http.get("/api/google-calendar/integrations/int-1/calendars", () => {
        return HttpResponse.json({
          success: true,
          data: mockCalendars,
        });
      }),
    );

    render(<GoogleCalendarSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText("test@example.com")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("test@example.com"));

    await waitFor(() => {
      expect(screen.getByText("Work Calendar")).toBeInTheDocument();
      expect(screen.getByText("Personal Calendar")).toBeInTheDocument();
    });

    // Checkbox is read-only, we click the parent div
    fireEvent.click(screen.getByText("Work Calendar"));
    fireEvent.click(screen.getByText("Personal Calendar"));

    const confirmBtn = screen.getByText(/Confirm Selection \(2 calendars\)/i);
    fireEvent.click(confirmBtn);

    expect(mockOnSelect).toHaveBeenCalledWith({
      GOOGLE_CALENDAR_INTEGRATION_ID: "int-1",
      CALENDAR_IDS: ["cal-1", "cal-2"],
    });

    expect(screen.getByText(/Configuration Complete/i)).toBeInTheDocument();
  });

  it("shows empty state when no integrations", async () => {
    server.use(
      http.get("/api/google-calendar/integrations", () => {
        return HttpResponse.json({
          success: true,
          data: [],
        });
      }),
    );

    render(<GoogleCalendarSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(
        screen.getByText(/No Google Calendar Connected/i),
      ).toBeInTheDocument();
    });
  });

  it("handles errors gracefully", async () => {
    server.use(
      http.get("/api/google-calendar/integrations", () => {
        return new HttpResponse(null, { status: 500 });
      }),
    );

    render(<GoogleCalendarSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(
        screen.getByText(/Failed to fetch Google Calendar integrations/i),
      ).toBeInTheDocument();
    });
  });
});
