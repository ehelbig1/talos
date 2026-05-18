import * as React from "react";
import { X } from "lucide-react";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { IconButton } from "@/components/ui/IconButton";

/**
 * Consistent header for dialogs that includes a title and a close button.
 * Mirrors the inline header previously duplicated in several modal components.
 */
export const ModalHeader: React.FC<{ title: string; onClose: () => void }> = ({
  title,
  onClose,
}) => (
  <header className="flex justify-between items-center mb-6">
    <SectionHeader level="h2" className="text-xl font-semibold m-0">
      {title}
    </SectionHeader>
    <IconButton onClick={onClose} aria-label="Close dialog">
      <X className="h-4 w-4" />
    </IconButton>
  </header>
);
