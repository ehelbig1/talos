import { create } from "zustand";
import { CompilationUpdate } from "@/lib/graphqlClient";

export interface CompilationJob extends CompilationUpdate {
  lastUpdated: number;
}

interface CompilationState {
  jobs: Record<string, CompilationJob>;
  updateJob: (event: CompilationUpdate) => void;
  removeJob: (jobId: string) => void;
  clearFinishedJobs: () => void;
}

export const useCompilationStore = create<CompilationState>((set) => ({
  jobs: {},
  updateJob: (event) =>
    set((state) => ({
      jobs: {
        ...state.jobs,
        [event.jobId]: {
          ...event,
          lastUpdated: Date.now(),
        },
      },
    })),
  removeJob: (jobId) =>
    set((state) => {
      const newJobs = { ...state.jobs };
      delete newJobs[jobId];
      return { jobs: newJobs };
    }),
  clearFinishedJobs: () =>
    set((state) => {
      const newJobs = { ...state.jobs };
      Object.keys(newJobs).forEach((id) => {
        const job = newJobs[id];
        if (job.status === "success" || job.status === "failed") {
          delete newJobs[id];
        }
      });
      return { jobs: newJobs };
    }),
}));
