import React from "react";
import { cn } from "@/lib/utils";
import { Circle } from "lucide-react";

interface RadioGroupItemProps {
  value: string;
  id?: string;
  className?: string;
  currentValue?: string;
  onValueChange?: (val: string) => void;
}

export const RadioGroup: React.FC<{
  value: string;
  onValueChange: (val: string) => void;
  children: React.ReactNode;
  className?: string;
}> = ({ value, onValueChange, children, className }) => {
  return (
    <div className={cn("grid gap-2", className)}>
      {React.Children.map(children, (child) => {
        if (React.isValidElement<RadioGroupItemProps>(child)) {
          const {
            currentValue: _cv,
            onValueChange: _ovc,
            ...rest
          } = child.props;
          return React.cloneElement(child, {
            ...rest,
            currentValue: value,
            onValueChange,
          } as Partial<RadioGroupItemProps>);
        }
        return child;
      })}
    </div>
  );
};

export const RadioGroupItem: React.FC<RadioGroupItemProps> = ({
  value,
  id,
  className,
  currentValue,
  onValueChange,
}) => {
  const checked = currentValue === value;
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      id={id}
      onClick={() => onValueChange?.(value)}
      className={cn(
        "aspect-square h-4 w-4 rounded-full border border-primary text-primary ring-offset-background focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
        checked && "bg-current",
        className,
      )}
    >
      {checked && (
        <span className="flex items-center justify-center">
          <Circle className="h-2.5 w-2.5 fill-current text-current" />
        </span>
      )}
    </button>
  );
};
