// @vitest-environment jsdom
import type { ComponentProps } from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { AuditLogTimeline } from "../components/audit/AuditLogTimeline";
import { ActivityEvent } from "../services/contract.service";

const AUDIT_ROW_HEIGHT = 100;
const VIEWPORT_HEIGHT = 576;

const stubRect = (height: number) => ({
  x: 0,
  y: 0,
  top: 0,
  left: 0,
  bottom: height,
  right: 900,
  width: 900,
  height,
  toJSON: () => ({}),
});

const buildActivity = (idx: number, overrides: Partial<ActivityEvent> = {}): ActivityEvent => ({
  action: `VAULT_EVENT_${idx}`,
  actor: `0x${idx.toString().padStart(4, "0")}`,
  timestamp: 1700000000 + idx,
  status: "success",
  ...overrides,
});

const buildActivities = (count: number): ActivityEvent[] =>
  Array.from({ length: count }, (_, i) => buildActivity(i + 1));

const renderTimeline = (
  activities: ActivityEvent[],
  overrides: Partial<ComponentProps<typeof AuditLogTimeline>> = {}
) => render(<AuditLogTimeline activities={activities} {...overrides} />);

const getMountedRowIndices = () =>
  screen.getAllByTestId("audit-log-row").map((row) => row.getAttribute("data-index"));

describe("AuditLogTimeline", () => {
  beforeEach(() => {
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (
      this: HTMLElement
    ) {
      if (this.getAttribute("data-testid") === "audit-log-row") {
        return stubRect(AUDIT_ROW_HEIGHT) as DOMRect;
      }
      return stubRect(VIEWPORT_HEIGHT) as DOMRect;
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows the empty-state message when there are no activities", () => {
    renderTimeline([]);
    expect(screen.getByText("No activity logs recorded yet.")).toBeInTheDocument();
    expect(screen.queryAllByTestId("audit-log-row")).toHaveLength(0);
  });

  it("renders every row when the list is smaller than the overscan window", () => {
    renderTimeline(buildActivities(5));
    expect(screen.getAllByTestId("audit-log-row")).toHaveLength(5);
  });

  it("keeps the mounted row count bounded when there are thousands of activity events", () => {
    const activities = buildActivities(10000);
    renderTimeline(activities);

    const mountedRows = screen.getAllByTestId("audit-log-row");
    expect(mountedRows.length).toBeGreaterThan(0);
    expect(mountedRows.length).toBeLessThan(50);
    expect(mountedRows.length).toBeLessThan(activities.length);
  });

  it("mounts only activities near the top of the list before scrolling", () => {
    renderTimeline(buildActivities(10000));

    const mountedIndices = getMountedRowIndices();
    expect(mountedIndices).toContain("0");
    expect(mountedIndices).not.toContain("9999");
  });

  it("swaps the mounted set of activities when the container is scrolled", () => {
    const activities = buildActivities(10000);
    const { container } = renderTimeline(activities);

    const scrollContainer = container.querySelector(
      '[data-testid="audit-log-scroll-container"]'
    ) as HTMLElement;
    expect(scrollContainer).toBeTruthy();

    const indicesBeforeScroll = new Set(getMountedRowIndices());
    expect(indicesBeforeScroll.has("0")).toBe(true);

    Object.defineProperty(scrollContainer, "scrollTop", {
      value: 5000 * AUDIT_ROW_HEIGHT,
      writable: true,
    });
    fireEvent.scroll(scrollContainer);

    const indicesAfterScroll = new Set(getMountedRowIndices());
    expect(indicesAfterScroll.has("0")).toBe(false);
    expect(
      [...indicesAfterScroll].some((index) => !indicesBeforeScroll.has(index as string))
    ).toBe(true);
  });

  it("renders the action label and actor for a virtualized row", () => {
    const activity = buildActivity(1, { action: "DOC_UPLOADED", actor: "0xabc123" });
    renderTimeline([activity]);

    expect(screen.getByText("DOC_UPLOADED")).toBeInTheDocument();
    expect(screen.getByText("0xabc123")).toBeInTheDocument();
  });

  it("renders a transaction link only when the activity has a txHash", () => {
    const withTx = buildActivity(1, { txHash: "0xdeadbeef", network: "avalanche" });
    renderTimeline([withTx]);
    expect(screen.getByText("Tx")).toBeInTheDocument();

    cleanup();

    const withoutTx = buildActivity(2, { txHash: undefined });
    renderTimeline([withoutTx]);
    expect(screen.queryByText("Tx")).not.toBeInTheDocument();
  });
});
