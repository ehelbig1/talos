import React from "react";
import { cn } from "@/lib/utils";

interface SectionHeaderProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode;
  level?: "h1" | "h2" | "h3" | "h4";
}

/**
 * The heading scale. Three sizes of heading plus one eyebrow (h4): the small
 * caps label that names a group of fields or a column. Weight steps down with
 * size so a page reads as one voice.
 */
export const SectionHeader: React.FC<SectionHeaderProps> = ({
  children,
  level = "h2",
  className,
  id,
  ...props
}) => {
  const Tag = level;

  const styles = {
    h1: "text-3xl sm:text-4xl font-bold tracking-tight text-white",
    h2: "text-xl sm:text-2xl font-semibold tracking-tight text-white",
    h3: "text-base sm:text-lg font-semibold tracking-tight text-white",
    h4: "text-2xs font-semibold uppercase tracking-wider text-muted-foreground",
  };

  return (
    <Tag
      id={id}
      className={cn(styles[level], "font-outfit", className)}
      {...props}
    >
      {children}
    </Tag>
  );
};
