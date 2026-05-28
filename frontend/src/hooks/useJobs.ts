import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listJobs, getJob, createJob, cancelJob, getResults, getToolsStatus,
  listJobHosts, cleanupJobHosts,
} from '../api/client'

export const useJobs = () =>
  useQuery({ queryKey: ['jobs'], queryFn: listJobs, refetchInterval: 5000 })

export const useJob = (id: string) =>
  useQuery({ queryKey: ['job', id], queryFn: () => getJob(id), refetchInterval: 3000 })

export const useResults = (jobId: string) =>
  useQuery({ queryKey: ['results', jobId], queryFn: () => getResults(jobId), refetchInterval: 5000 })

export const useToolsStatus = () =>
  useQuery({ queryKey: ['tools'], queryFn: getToolsStatus, staleTime: 30_000 })

export const useCreateJob = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: createJob,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  })
}

export const useCancelJob = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: cancelJob,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  })
}

export const useJobHosts = (jobId: string) =>
  useQuery({
    queryKey: ['job-hosts', jobId],
    queryFn: () => listJobHosts(jobId),
    enabled: !!jobId,
    refetchInterval: 5000,
  })

export const useCleanupJobHosts = (jobId: string) => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => cleanupJobHosts(jobId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['job-hosts', jobId] }),
  })
}
