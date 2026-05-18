import { Database, Cpu, HardDrive, Network, Box } from "lucide-react";
import type { ElementType } from "react";

export const getCategoryIcon = (category?: string): ElementType => {
  switch (category?.toLowerCase()) {
    case "data":
      return Database;
    case "ai":
      return Cpu;
    case "storage":
      return HardDrive;
    case "network":
      return Network;
    default:
      return Box;
  }
};

export const getCategoryColor = (category?: string): string => {
  switch (category?.toLowerCase()) {
    case "data":
      return "text-blue-400";
    case "ai":
      return "text-purple-400";
    case "storage":
      return "text-amber-400";
    case "network":
      return "text-green-400";
    default:
      return "text-gray-400";
  }
};
