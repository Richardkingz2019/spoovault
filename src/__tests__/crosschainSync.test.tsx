// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import * as Web3Context from "../context/Web3Context";

vi.mock("../context/Web3Context", () => ({
  useWeb3: vi.fn(),
}));

vi.mock("../services/contract.service", () => ({
  contractService: {
    initialize: vi.fn(),
    getVaultsByCreator: vi.fn().mockResolvedValue([]),
    getDocumentsByVault: vi.fn().mockResolvedValue([]),
    getPendingRequestsForUser: vi.fn().mockResolvedValue([]),
    getApprovalThreshold: vi.fn().mockResolvedValue(1),
    isGuardianOf: vi.fn().mockResolvedValue(false),
  },
}));

vi.mock("../services/stellar.service", () => ({
  stellarContractService: {
    initialize: vi.fn(),
    getVaultsByCreator: vi.fn().mockResolvedValue([]),
    getDocumentsByVault: vi.fn().mockResolvedValue([]),
  },
}));

// Mock heroui components
vi.mock("@heroui/react", () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardBody: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  Input: (props: any) => <input {...props} />,
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
  Chip: ({ children }: any) => <span>{children}</span>,
  Modal: ({ children, isOpen }: any) => isOpen ? <div>{children}</div> : null,
  ModalContent: ({ children }: any) => <div>{children}</div>,
  ModalHeader: ({ children }: any) => <div>{children}</div>,
  ModalBody: ({ children }: any) => <div>{children}</div>,
  ModalFooter: ({ children }: any) => <div>{children}</div>,
  useDisclosure: vi.fn(() => ({
    isOpen: false,
    onOpen: vi.fn(),
    onClose: vi.fn(),
  })),
  Textarea: (props: any) => <textarea {...props} />,
  Badge: ({ children }: any) => <div>{children}</div>,
  Avatar: () => <div />,
  Skeleton: ({ children }: any) => <div>{children}</div>,
  Table: ({ children }: any) => <table>{children}</table>,
  TableHeader: ({ children }: any) => <thead>{children}</thead>,
  TableColumn: ({ children }: any) => <th>{children}</th>,
  TableBody: ({ children }: any) => <tbody>{children}</tbody>,
  TableRow: ({ children }: any) => <tr>{children}</tr>,
  TableCell: ({ children }: any) => <td>{children}</td>,
}));

import Vaults from "../pages/Vaults";
import Documents from "../pages/Documents";
import AccessCenter from "../pages/AccessCenter";

describe("CrossChain/Sync UI State Flushing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (Web3Context.useWeb3 as any).mockReturnValue({
      account: "0x1234567890123456789012345678901234567890",
      isConnected: true,
      connect: vi.fn(),
      provider: {},
      signer: {},
      isFujiNetwork: true,
      ecosystem: "avalanche",
      chainId: 43113,
    });
  });

  it("Vaults.tsx should mount cleanly and handle ecosystem context", () => {
    expect(() => {
      render(
        <MemoryRouter>
          <Vaults />
        </MemoryRouter>
      );
    }).not.toThrow();
  });

  it("Documents.tsx should mount cleanly and handle ecosystem context", () => {
    expect(() => {
      render(
        <MemoryRouter>
          <Documents />
        </MemoryRouter>
      );
    }).not.toThrow();
  });

  it("AccessCenter.tsx should mount cleanly and handle ecosystem context", () => {
    expect(() => {
      render(
        <MemoryRouter>
          <AccessCenter />
        </MemoryRouter>
      );
    }).not.toThrow();
  });
});

