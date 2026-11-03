import { z } from 'zod';

export const paginationQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25), // cap protects the DB
});

export type PaginationQuery = z.infer<typeof paginationQuery>;

export function skipTake({ page, pageSize }: PaginationQuery) {
  return { skip: (page - 1) * pageSize, take: pageSize };
}

export function paginated<T>(data: T[], total: number, { page, pageSize }: PaginationQuery) {
  return { data, pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } };
}
