import React from "react";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from "../../../test-utils";
import { AuthForm } from "../AuthForm";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { login as authLogin, verifyTwoFactor } from "@/lib/auth";
import { useAuth } from "@/contexts/AuthContext";

// Mock the auth library
vi.mock("@/lib/auth", () => ({
  login: vi.fn(),
  signup: vi.fn(),
  verifyTwoFactor: vi.fn(),
}));

// Mock the auth context
vi.mock("@/contexts/AuthContext", () => ({
  useAuth: vi.fn(),
}));

describe("AuthForm", () => {
  const mockSetAuthUser = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    (useAuth as any).mockReturnValue({
      login: mockSetAuthUser,
    });
  });

  it("renders login form by default", () => {
    render(<AuthForm />);
    expect(screen.getByPlaceholderText("you@example.com")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("••••••••")).toBeInTheDocument();
    const form = screen.getByRole("form", { name: /auth-form/i });
    expect(
      within(form).getByRole("button", { name: /Login/i }),
    ).toBeInTheDocument();
  });

  it("transitions to 2FA step when login requires 2FA", async () => {
    const mockUser = {
      id: "1",
      email: "test@example.com",
      twoFactorEnabled: true,
    };
    (authLogin as any).mockResolvedValue({ user: mockUser });

    render(<AuthForm />);

    fireEvent.change(screen.getByPlaceholderText("you@example.com"), {
      target: { value: "test@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "password123" },
    });

    const form = screen.getByRole("form", { name: /auth-form/i });
    fireEvent.click(within(form).getByRole("button", { name: /Login/i }));

    await waitFor(() => {
      expect(
        screen.getByText(/Please enter the 6-digit code/i),
      ).toBeInTheDocument();
      expect(screen.getByPlaceholderText("000000")).toBeInTheDocument();
    });

    expect(mockSetAuthUser).toHaveBeenCalledWith(mockUser);
  });

  it("calls verifyTwoFactor and completes login on successful 2FA", async () => {
    const mockUser = {
      id: "1",
      email: "test@example.com",
      twoFactorEnabled: true,
    };
    (authLogin as any).mockResolvedValue({ user: mockUser });
    (verifyTwoFactor as any).mockResolvedValue(mockUser);

    render(<AuthForm />);

    // Step 1: Login
    fireEvent.change(screen.getByPlaceholderText("you@example.com"), {
      target: { value: "test@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "password123" },
    });

    const form = screen.getByRole("form", { name: /auth-form/i });
    fireEvent.click(within(form).getByRole("button", { name: /Login/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText("000000")).toBeInTheDocument();
    });

    // Step 2: 2FA
    fireEvent.change(screen.getByPlaceholderText("000000"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Verify & Login/i }));

    await waitFor(() => {
      expect(verifyTwoFactor).toHaveBeenCalledWith("123456");
      expect(mockSetAuthUser).toHaveBeenCalledWith(mockUser);
    });
  });

  it("shows error message if 2FA verification fails", async () => {
    const mockUser = {
      id: "1",
      email: "test@example.com",
      twoFactorEnabled: true,
    };
    (authLogin as any).mockResolvedValue({ user: mockUser });
    (verifyTwoFactor as any).mockRejectedValue(new Error("Invalid 2FA code"));

    render(<AuthForm />);

    // Step 1: Login
    fireEvent.change(screen.getByPlaceholderText("you@example.com"), {
      target: { value: "test@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "password123" },
    });

    const form = screen.getByRole("form", { name: /auth-form/i });
    fireEvent.click(within(form).getByRole("button", { name: /Login/i }));

    await waitFor(() => {
      expect(screen.getByPlaceholderText("000000")).toBeInTheDocument();
    });

    // Step 2: 2FA failure
    fireEvent.change(screen.getByPlaceholderText("000000"), {
      target: { value: "wrong!!" },
    });
    const authForm = screen.getByRole("form", { name: /two-factor-form/i });
    fireEvent.submit(authForm);

    await waitFor(() => {
      expect(screen.getByText("Invalid 2FA code")).toBeInTheDocument();
    });
  });
});
