/**
 * A tiny typed registry.
 *
 * Attacks, oracles, and adapters each live in one of these so the CLI/runner can
 * resolve them by stable string id, list them for `--suite` selection, and stay
 * open to extension without touching the runner. Each registered item must carry
 * a unique `id`.
 */

export interface Identified {
  readonly id: string;
}

export class Registry<T extends Identified> {
  private readonly items = new Map<string, T>();

  constructor(private readonly kind: string) {}

  /** Register an item. Throws on duplicate id — silent overwrite hides bugs. */
  register(item: T): this {
    if (this.items.has(item.id)) {
      throw new Error(`${this.kind}: duplicate id "${item.id}"`);
    }
    this.items.set(item.id, item);
    return this;
  }

  /** Register many, in order. */
  registerAll(items: readonly T[]): this {
    for (const item of items) this.register(item);
    return this;
  }

  has(id: string): boolean {
    return this.items.has(id);
  }

  /** Resolve by id or throw a helpful error listing what IS available. */
  get(id: string): T {
    const item = this.items.get(id);
    if (!item) {
      throw new Error(`${this.kind}: unknown id "${id}". Available: ${this.ids().join(', ') || '(none)'}`);
    }
    return item;
  }

  ids(): string[] {
    return [...this.items.keys()];
  }

  list(): T[] {
    return [...this.items.values()];
  }

  get size(): number {
    return this.items.size;
  }
}
