import type { StoreInjectionClient } from './store-injection-server.ts';

type MessageStoreOptions = {
  signal?: AbortSignal;
};

type MessageSort = Record<string, number | undefined>;

type Pagination = {
  cursor?: { messageCid: string; value?: unknown };
  limit?: number;
};

type Filter = Record<string, unknown>;

function checkAborted(options?: MessageStoreOptions): void {
  if (options?.signal?.aborted === true) {
    throw options.signal.reason ?? new Error('Aborted');
  }
}

export function createRustSqliteMessageStore(client: StoreInjectionClient) {
  return {
    async open(): Promise<void> {
      await client.call('open');
    },

    async close(): Promise<void> {
      await client.call('close');
    },

    async clear(): Promise<void> {
      await client.call('clear');
    },

    async put(
      tenant: string,
      message: Record<string, unknown>,
      indexes: Record<string, unknown>,
      options?: MessageStoreOptions,
    ): Promise<void> {
      checkAborted(options);
      await client.call('put', { tenant, message, indexes });
    },

    async get(
      tenant: string,
      cid: string,
      options?: MessageStoreOptions,
    ): Promise<Record<string, unknown> | undefined> {
      checkAborted(options);
      const result = await client.call('get', { tenant, cid });
      return result === null ? undefined : result as Record<string, unknown>;
    },

    async query(
      tenant: string,
      filters: Filter[],
      messageSort?: MessageSort,
      pagination?: Pagination,
      options?: MessageStoreOptions,
    ): Promise<{ messages: Record<string, unknown>[]; cursor?: unknown }> {
      checkAborted(options);
      const result = await client.call('query', {
        tenant,
        filters,
        messageSort,
        pagination,
      }) as { messages?: Record<string, unknown>[]; cursor?: unknown };
      return {
        messages: result.messages ?? [],
        cursor: result.cursor ?? undefined,
      };
    },

    async count(
      tenant: string,
      filters: Filter[],
      messageSort?: MessageSort,
      options?: MessageStoreOptions,
    ): Promise<number> {
      checkAborted(options);
      const result = await client.call('count', { tenant, filters, messageSort });
      return result as number;
    },

    async delete(
      tenant: string,
      cid: string,
      options?: MessageStoreOptions,
    ): Promise<void> {
      checkAborted(options);
      await client.call('delete', { tenant, cid });
    },
  };
}

export type RustSqliteMessageStore = ReturnType<typeof createRustSqliteMessageStore>;
