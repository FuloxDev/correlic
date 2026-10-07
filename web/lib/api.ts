const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

interface ApiOptions {
  method?: string;
  body?: unknown;
  token?: string;
}

export async function api<T = unknown>(
  path: string,
  { method = "GET", body, token }: ApiOptions = {}
): Promise<{ data?: T; error?: string; status: number }> {
  const headers: Record<string, string> = {};
  if (body) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "include",
    });

    const data = await res.json();

    if (!res.ok) {
      return { error: data.message || "Something went wrong", status: res.status };
    }

    return { data, status: res.status };
  } catch {
    return { error: "Network error — is the API running?", status: 0 };
  }
}

// ── Posts ──────────────────────────────────────────────────────

export interface Post {
  id: string;
  title: string;
  slug: string;
  type: "video" | "article";
  externalUrl: string | null;
  excerpt: string | null;
  content?: string | null;
  thumbnailUrl: string | null;
  mediaUrl: string | null;
  mediaDuration: number | null;
  authorName: string;
  published?: boolean;
  publishedAt: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export async function fetchLatestPosts() {
  return api<{ posts: Post[] }>("/posts/latest");
}

export async function fetchPosts(params?: {
  type?: string;
  page?: number;
  limit?: number;
  search?: string;
}) {
  const query = new URLSearchParams();
  if (params?.type) query.set("type", params.type);
  if (params?.page) query.set("page", String(params.page));
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.search) query.set("search", params.search);

  const qs = query.toString();
  return api<{ posts: Post[]; total: number; page: number; limit: number }>(
    `/posts${qs ? `?${qs}` : ""}`
  );
}

export async function fetchPostBySlug(slug: string) {
  return api<Post>(`/posts/${slug}`);
}
