import React, { useState } from "react";
import { scrollableStyle } from "@/components/ui/theme";
import { Dialog } from "@/components/ui/dialog";
import { FlexContainer } from "@/components/ui/FlexContainer";
import { grayBorderStyle } from "@/components/ui/theme";
import { SectionHeader } from "@/components/ui";
import {
  Search,
  Users,
  X,
  Lock,
  Hash,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";

interface SlackBrowserProps {
  botToken: string | undefined;
  fieldName: string;
  currentValue: string[];
  onSelect: (values: string[]) => void;
  resourceType: "channels" | "users";
}

interface SlackChannel {
  id: string;
  name: string;
  is_private?: boolean;
  num_members?: number;
  topic?: {
    value: string;
  };
}

interface SlackUser {
  id: string;
  name: string;
  real_name?: string;
  profile?: {
    email?: string;
    display_name?: string;
  };
  deleted?: boolean;
  is_bot?: boolean;
}

export function SlackBrowser({
  botToken,
  currentValue,
  onSelect,
  resourceType,
}: SlackBrowserProps) {
  const [loading, setLoading] = useState(false);
  const [resources, setResources] = useState<(SlackChannel | SlackUser)[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showBrowser, setShowBrowser] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(
    new Set(currentValue),
  );

  const fetchResources = async () => {
    if (!botToken) {
      setError("Bot token is required to browse Slack resources");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const endpoint =
        resourceType === "channels"
          ? "/api/slack/channels"
          : "/api/slack/users";
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "include", // Send cookies with request
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ bot_token: botToken }),
      });

      if (!response.ok) {
        throw new Error(
          `Failed to fetch ${resourceType}: ${response.statusText}`,
        );
      }

      const data = await response.json();

      if (!data.ok) {
        throw new Error(data.error || `Failed to fetch ${resourceType}`);
      }

      // Extract channels or members from response
      const items =
        resourceType === "channels"
          ? data.data?.channels || []
          : data.data?.members || [];

      // Filter out deleted users and bots if fetching users
      const filtered =
        resourceType === "users"
          ? items.filter((u: SlackUser) => !u.deleted && !u.is_bot)
          : items;

      setResources(filtered);
      setShowBrowser(true);
    } catch (err) {
      setError(
        sanitizeErrorMessage(
          err instanceof Error ? err.message : "Unknown error",
        ),
      );
    } finally {
      setLoading(false);
    }
  };

  const toggleSelection = (id: string) => {
    const newSet = new Set(selectedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedIds(newSet);
  };

  const handleApply = () => {
    onSelect(Array.from(selectedIds));
    setShowBrowser(false);
  };

  const handleCancel = () => {
    setSelectedIds(new Set(currentValue));
    setShowBrowser(false);
  };

  if (!showBrowser) {
    return (
      <div style={{ marginTop: "0.5rem" }}>
        <button
          type="button"
          onClick={fetchResources}
          disabled={loading || !botToken}
          style={{
            padding: "0.375rem 0.75rem",
            background: botToken ? "#10b981" : "#ccc",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: botToken ? "pointer" : "not-allowed",
            fontSize: "0.75rem",
            fontWeight: "bold",
            display: "flex",
            alignItems: "center",
            gap: "0.25rem",
          }}
          title={!botToken ? "Configure BOT_TOKEN first" : ""}
        >
          {loading ? (
            <>
              <Loader2 className="h-3 w-3 animate-spin" /> Loading...
            </>
          ) : (
            <>
              <Search className="h-3 w-3" /> Browse{" "}
              {resourceType === "channels" ? "Channels" : "Users"}
            </>
          )}
        </button>

        {error && (
          <p
            style={{ marginTop: "0.5rem", fontSize: "0.75rem", color: "#f44" }}
            className="flex items-center gap-1"
          >
            <AlertTriangle className="h-3 w-3" /> {error}
          </p>
        )}
      </div>
    );
  }

  return (
    <Dialog open={true} onClose={handleCancel} title="Slack Browser">
      <div
        style={{
          background: "white",
          borderRadius: "8px",
          padding: "1.5rem",
          maxWidth: "600px",
          width: "90%",
          maxHeight: "80vh",
          display: "flex",
          flexDirection: "column",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "1rem",
          }}
        >
          <SectionHeader
            level="h3"
            className="m-0 text-xl font-bold flex items-center gap-2"
          >
            {resourceType === "channels" ? (
              <>
                <Hash className="h-5 w-5 text-indigo-500" /> Select Channels
              </>
            ) : (
              <>
                <Users className="h-5 w-5 text-indigo-500" /> Select Users
              </>
            )}
          </SectionHeader>
          <button
            type="button"
            onClick={handleCancel}
            className="flex items-center justify-center p-1 rounded-md bg-transparent hover:bg-white/10 text-muted-foreground transition-premium cursor-pointer border-none"
            title="Close"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <p
          style={{ margin: "0 0 1rem 0", fontSize: "0.875rem", color: "#666" }}
        >
          {selectedIds.size} selected
        </p>

        <div
          style={{
            flex: 1,
            borderRadius: "4px",
            marginBottom: "1rem",
            ...grayBorderStyle,
            ...(scrollableStyle as React.CSSProperties),
          }}
        >
          {resources.length === 0 ? (
            <p style={{ padding: "2rem", textAlign: "center", color: "#666" }}>
              No {resourceType} found
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column" }}>
              {resources.map((resource) => {
                const isChannel = resourceType === "channels";
                const channel = resource as SlackChannel;
                const user = resource as SlackUser;
                const isSelected = selectedIds.has(resource.id);

                return (
                  <div
                    key={resource.id}
                    onClick={() => toggleSelection(resource.id)}
                    style={{
                      padding: "0.75rem 1rem",
                      borderBottom: "1px solid #f3f4f6",
                      cursor: "pointer",
                      background: isSelected ? "#e8f4fd" : "white",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) {
                        e.currentTarget.style.background = "#f9fafb";
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) {
                        e.currentTarget.style.background = "white";
                      }
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.75rem",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}}
                        style={{ cursor: "pointer" }}
                      />
                      <div style={{ flex: 1 }}>
                        <div
                          style={{
                            fontWeight: "bold",
                            fontSize: "0.875rem",
                            marginBottom: "0.25rem",
                          }}
                        >
                          {isChannel ? (
                            <div className="flex items-center gap-1">
                              {channel.is_private ? (
                                <Lock className="h-3 w-3 text-muted-foreground" />
                              ) : (
                                <Hash className="h-3 w-3 text-muted-foreground" />
                              )}{" "}
                              {channel.name}
                            </div>
                          ) : (
                            <>
                              {user.profile?.display_name ||
                                user.real_name ||
                                user.name}
                            </>
                          )}
                        </div>
                        <div style={{ fontSize: "0.75rem", color: "#666" }}>
                          {isChannel ? (
                            <>
                              {channel.num_members &&
                                `${channel.num_members} members`}
                              {channel.topic?.value &&
                                ` • ${channel.topic.value.substring(0, 60)}${channel.topic.value.length > 60 ? "..." : ""}`}
                            </>
                          ) : (
                            <>{user.profile?.email || `@${user.name}`}</>
                          )}
                        </div>
                        <div
                          style={{
                            fontSize: "0.65rem",
                            color: "#999",
                            marginTop: "0.25rem",
                            fontFamily: "monospace",
                          }}
                        >
                          {resource.id}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <FlexContainer gap="0.5rem" justify="end">
          <button
            type="button"
            onClick={handleCancel}
            style={{
              padding: "0.5rem 1rem",
              background: "white",
              color: "#666",
              border: "1px solid #ccc",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "0.875rem",
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleApply}
            style={{
              padding: "0.5rem 1rem",
              background: "#0084ff",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "0.875rem",
              fontWeight: "bold",
            }}
          >
            Apply Selection
          </button>
        </FlexContainer>
      </div>
    </Dialog>
  );
}
