"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "./dialog";

interface ConfirmDialogProps {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  title: string;
  description: string;
  confirmLabel?: string;
  confirmVariant?: "danger" | "success";
  children?: React.ReactNode;
}

export function ConfirmDialog({
  open,
  onConfirm,
  onCancel,
  title,
  description,
  confirmLabel = "Confirm",
  confirmVariant = "danger",
  children,
}: ConfirmDialogProps) {
  const confirmColors =
    confirmVariant === "danger"
      ? "bg-red-500/20 border-red-500/30 text-red-400 hover:bg-red-500/30 hover:shadow-lg hover:shadow-red-500/5 hover:border-red-500/40"
      : "bg-green-500/20 border-green-500/30 text-green-400 hover:bg-green-500/30 hover:shadow-lg hover:shadow-green-500/5 hover:border-green-500/40";

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onCancel(); }}>
      <DialogContent className="bg-gray-900 border-gray-700 text-white sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-white">{title}</DialogTitle>
          <DialogDescription className="text-gray-400">
            {description}
          </DialogDescription>
        </DialogHeader>
        {children}
        <DialogFooter className="flex gap-2 sm:justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-white/5 border border-gray-600 text-gray-300 rounded-xl text-sm font-semibold hover:bg-white/[0.08] hover:border-white/20 transition-all duration-200"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 border rounded-xl text-sm font-semibold transition-all duration-200 ${confirmColors}`}
          >
            {confirmLabel}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
