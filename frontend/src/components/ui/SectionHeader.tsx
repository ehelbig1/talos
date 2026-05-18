import React from "react";
import { cn } from "@/lib/utils";

interface SectionHeaderProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode;
  level?: "h1" | "h2" | "h3" | "h4";
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  children,
  level = "h2",
  className,
  id,
  ...props
}) => {
  const Tag = level;
  
  const styles = {
    h1: "text-4xl sm:text-5xl font-black tracking-tighter text-white",
    h2: "text-2xl sm:text-3xl font-black tracking-tight text-white",
    h3: "text-lg sm:text-xl font-black tracking-tight text-white",
    h4: "text-sm font-black uppercase tracking-widest text-muted-foreground/60",
  };

  return (
    <Tag id={id} className={cn(styles[level], "font-outfit", className)} {...props}>
      {children}
    </Tag>
  );
};
