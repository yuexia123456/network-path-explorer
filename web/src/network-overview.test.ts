import { afterEach, expect, test, vi } from "vitest";
import { createNetworkOverview, createNetworkOverviewLoading } from "./network-overview";
import { degradingOverview, localNetworkOverview } from "./test-fixtures";
import type { ApiClient } from "./api";
import type { NetworkOverviewResponse } from "./types";

const unavailableOverview: NetworkOverviewResponse = {
  local: {
    ...localNetworkOverview,
    mihomo: {
      available: false,
      mode: null,
      tun_enabled: null,
      controller: "unavailable"
    }
  },
  egress: null,
  egress_error: "egress_unavailable"
};

function actions(
  setMihomoController = vi.fn<Pick<ApiClient, "setMihomoController">["setMihomoController"]>(
    async () => ({ available: true, mode: "rule", tun_enabled: true, controller: "manual_loopback" })
  ),
  resetMihomoController = vi.fn<Pick<ApiClient, "resetMihomoController">["resetMihomoController"]>(
    async () => ({ available: false, mode: null, tun_enabled: null, controller: "unavailable" })
  ),
  onRefresh = vi.fn(async (): Promise<void> => undefined)
) {
  return {
    api: { setMihomoController, resetMihomoController },
    onRefresh,
    setMihomoController,
    resetMihomoController
  };
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>((next) => { resolve = next; }), resolve };
}

afterEach(() => {
  document.body.replaceChildren();
  window.localStorage.clear();
  window.sessionStorage.clear();
  vi.restoreAllMocks();
});

test("orders default physical, TUN, other active, then loopback interfaces", () => {
  const response: NetworkOverviewResponse = {
    ...degradingOverview,
    local: {
      ...localNetworkOverview,
      interfaces: [
        {
          name: "lo0",
          display_name: "Loopback",
          kind: "loopback",
          is_default: false,
          addresses: [{ ip: "127.0.0.1", scope: "loopback" }]
        },
        {
          name: "en5",
          display_name: "USB Ethernet",
          kind: "ethernet",
          is_default: false,
          addresses: [{ ip: "203.0.113.25", scope: "global" }]
        },
        localNetworkOverview.interfaces[1]!,
        localNetworkOverview.interfaces[0]!
      ]
    }
  };

  const card = createNetworkOverview(response);

  expect(
    Array.from(card.querySelectorAll<HTMLElement>("[data-interface-name]")).map(
      (item) => item.dataset.interfaceName
    )
  ).toEqual(["en0", "utun4", "en5", "lo0"]);
  expect(card.textContent).toContain("局域网");
  expect(card.textContent).toContain("公网地址");
  expect(card.textContent).toContain("链路本地");
  expect(card.textContent).toContain("本机内部地址");
});

test("isolates the ipify egress IP and its own Clash decision", () => {
  const card = createNetworkOverview(degradingOverview);

  expect(card.querySelector('[data-overview-field="egress-ip"]')?.textContent).toBe(
    "203.0.113.7"
  );
  expect(card.querySelector('[data-overview-field="egress-decision"]')?.textContent).toContain(
    "UNKNOWN"
  );
  expect(card.querySelector('[data-overview-field="egress-decision"]')?.textContent).toContain(
    "未知"
  );
  expect(card.querySelector('[data-overview-field="egress-ip"]')?.textContent).not.toContain(
    "192.168.1.8"
  );
  expect(card.querySelector('[data-overview-field="tun-status"]')?.textContent).toBe("已开启");
  expect(card.querySelector('[data-overview-field="system-proxy"]')?.textContent).toContain(
    "与 TUN 是两种不同入口"
  );
});

test("discloses the isolated ipify request before overview loading", () => {
  const loading = createNetworkOverviewLoading();

  expect(loading.getAttribute("aria-busy")).toBe("true");
  expect(loading.textContent).toContain("ipify 只会收到这次公网 IP 查询");
});

test("shows unknown public egress without promoting a local address", () => {
  const card = createNetworkOverview(unavailableOverview);

  expect(card.textContent).toContain("公网出口暂时无法确认");
  expect(card.querySelector('[data-overview-field="egress-ip"]')).toBeNull();
  expect(card.textContent).not.toContain("公网出口 IP：192.168.1.8");
});

test("manual controller validation stays advisory and clears the password on failure", async () => {
  window.localStorage.setItem("existing", "keep");
  window.sessionStorage.setItem("existing", "keep");
  const failure = new Error("backend rejected non-loopback controller");
  const setMihomoController = vi.fn(async () => Promise.reject(failure));
  const configured = actions(setMihomoController);
  const card = createNetworkOverview(unavailableOverview, configured);
  document.body.append(card);
  const details = card.querySelector<HTMLDetailsElement>("details");
  const form = card.querySelector<HTMLFormElement>("form");
  const controller = card.querySelector<HTMLInputElement>('[name="controller-url"]');
  const password = card.querySelector<HTMLInputElement>('[name="controller-secret"]');
  if (!details || !form || !controller || !password) throw new Error("manual form is missing");

  expect(details.open).toBe(false);
  expect(details.querySelector("summary")?.textContent).toBe("高级设置：手动连接本机 Clash");
  expect(password.autocomplete).toBe("off");
  expect(card.textContent).toContain("仅支持本机回环地址");
  controller.value = "http://example.com:9090";
  password.value = "do-not-retain";
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

  await vi.waitFor(() => expect(setMihomoController).toHaveBeenCalledOnce());
  await vi.waitFor(() => expect(password.value).toBe(""));
  expect(setMihomoController).toHaveBeenCalledWith(
    "http://example.com:9090",
    "do-not-retain"
  );
  expect(configured.onRefresh).not.toHaveBeenCalled();
  expect(window.localStorage.getItem("existing")).toBe("keep");
  expect(window.sessionStorage.getItem("existing")).toBe("keep");
  expect(document.body.textContent).not.toContain("do-not-retain");
});

test("successful manual set and reset refresh only sanitized overview state", async () => {
  const configured = actions();
  const card = createNetworkOverview(unavailableOverview, configured);
  document.body.append(card);
  const form = card.querySelector<HTMLFormElement>("form");
  const controller = card.querySelector<HTMLInputElement>('[name="controller-url"]');
  const password = card.querySelector<HTMLInputElement>('[name="controller-secret"]');
  const reset = card.querySelector<HTMLButtonElement>('[data-action="reset-controller"]');
  if (!form || !controller || !password || !reset) throw new Error("manual controls are missing");

  controller.value = "http://127.0.0.1:9090";
  password.value = "temporary";
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(configured.onRefresh).toHaveBeenCalledTimes(1));
  expect(password.value).toBe("");

  reset.click();
  await vi.waitFor(() => expect(configured.resetMihomoController).toHaveBeenCalledOnce());
  await vi.waitFor(() => expect(configured.onRefresh).toHaveBeenCalledTimes(2));
});

test("keeps reset-to-auto available for an active manual loopback controller", () => {
  const configured = actions();
  const card = createNetworkOverview(
    {
      ...degradingOverview,
      local: {
        ...localNetworkOverview,
        mihomo: {
          available: true,
          mode: "rule",
          tun_enabled: true,
          controller: "manual_loopback"
        }
      }
    },
    configured
  );

  expect(card.querySelector('[data-action="reset-controller"]')).not.toBeNull();
});

test("clears the password before a sanitized overview refresh can settle", async () => {
  const refresh = deferred<void>();
  const configured = actions(undefined, undefined, vi.fn(() => refresh.promise));
  const card = createNetworkOverview(unavailableOverview, configured);
  document.body.append(card);
  const form = card.querySelector<HTMLFormElement>("form");
  const controller = card.querySelector<HTMLInputElement>('[name="controller-url"]');
  const password = card.querySelector<HTMLInputElement>('[name="controller-secret"]');
  if (!form || !controller || !password) throw new Error("manual controls are missing");

  controller.value = "http://127.0.0.1:9090";
  password.value = "clear-before-refresh";
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(configured.onRefresh).toHaveBeenCalledOnce());

  expect(password.value).toBe("");
  refresh.resolve(undefined);
});
