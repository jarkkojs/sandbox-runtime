import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse, resolve } from 'node:path'
import { quote } from '../utils/shell-quote.js'
import { buildJavaToolOptions } from './java-proxy-agent.js'
import {
  buildPosixGitSafeDirEnv,
  DANGEROUS_FILES,
  encodeSandboxedCommand,
  generateProxyEnvVars,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'

type LandstripPlatform = 'linux' | 'macos'

export interface LandstripPolicy {
  filesystem: {
    denyRead: string[]
    allowRead: string[]
    allowWrite: string[]
    denyWrite: string[]
  }
  network: {
    allowNetwork: boolean
    allowLocalBinding: boolean
    allowAllUnixSockets: boolean
    allowUnixSockets: string[]
    httpProxyPort?: number
    socksProxyPort?: number
  }
  windows: {
    appContainerMode: 'lpac' | 'standard'
    allowLoopback: boolean
  }
}

export interface LandstripShell {
  exe: string
  args: readonly string[]
}

export interface BuildLandstripPolicyOptions {
  platform: LandstripPlatform
  cwd: string
  shell: LandstripShell
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  allowLocalBinding?: boolean
  allowUnixSockets?: readonly string[]
  allowAllUnixSockets?: boolean
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  mandatoryDenyWrite?: readonly string[]
  maskedFileBinds?: ReadonlyArray<{ realPath: string; fakePath: string }>
}

export interface WrapCommandWithLandstripOptions
  extends BuildLandstripPolicyOptions {
  landstripPath: string
  command: string
  commandId?: string
  proxyAuthToken?: string
  caCertPath?: string
  javaAgentJarPath?: string
  unsetEnvVars?: readonly string[]
  setEnvVars?: Readonly<Record<string, string>>
  gitSafeDirectories?: readonly string[]
}

export interface LandstripInvocation {
  argv: string[]
  env: NodeJS.ProcessEnv
  policyPath: string
}

let policyDirectory: string | undefined
let policySequence = 0

function unique(paths: readonly string[]): string[] {
  return [...new Set(paths)]
}

function policyDirectoryPath(): string {
  policyDirectory ??= mkdtempSync(join(tmpdir(), 'sandbox-runtime-landstrip-'))
  return policyDirectory
}

export function writeLandstripPolicy(policy: LandstripPolicy): string {
  const policyPath = join(
    policyDirectoryPath(),
    `policy-${process.pid}-${policySequence++}.json`,
  )
  writeFileSync(policyPath, JSON.stringify(policy), {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  })
  return policyPath
}

export function cleanupLandstripPolicies(): void {
  if (policyDirectory !== undefined) {
    rmSync(policyDirectory, { recursive: true, force: true })
    policyDirectory = undefined
  }
  policySequence = 0
}

/** Mandatory write denials shared by the legacy wrappers and Landstrip. */
export function getLandstripMandatoryDenyWrite(
  cwd: string,
  allowGitConfig = false,
): string[] {
  const deny: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    deny.push(resolve(cwd, fileName), resolve(cwd, '**', fileName))
  }
  for (const directoryName of getDangerousDirectories()) {
    deny.push(
      resolve(cwd, directoryName),
      resolve(cwd, '**', directoryName),
      resolve(cwd, '**', directoryName, '**'),
    )
  }
  deny.push(
    resolve(cwd, '.git', 'hooks'),
    resolve(cwd, '**', '.git', 'hooks'),
    resolve(cwd, '**', '.git', 'hooks', '**'),
  )
  if (!allowGitConfig) {
    deny.push(
      resolve(cwd, '.git', 'config'),
      resolve(cwd, '**', '.git', 'config'),
    )
  }
  return unique(deny)
}

export function buildLandstripPolicy(
  options: BuildLandstripPolicyOptions,
): LandstripPolicy {
  const { cwd, needsNetworkRestriction, readConfig, writeConfig } = options

  const denyRead = readConfig ? [...readConfig.denyOnly] : []
  const allowRead = readConfig ? [...(readConfig.allowWithinDeny ?? [])] : []
  const allowWrite = writeConfig
    ? [...writeConfig.allowOnly]
    : [parse(resolve(cwd)).root]
  const denyWrite = writeConfig
    ? [...writeConfig.denyWithinAllow, ...(options.mandatoryDenyWrite ?? [])]
    : []

  if (options.maskedFileBinds?.length) {
    denyRead.push(...options.maskedFileBinds.map(binding => binding.realPath))
  }

  return {
    filesystem: {
      denyRead: unique(denyRead),
      allowRead: unique(allowRead),
      allowWrite: unique(allowWrite),
      denyWrite: unique(denyWrite),
    },
    network: {
      allowNetwork: !needsNetworkRestriction,
      allowLocalBinding: options.allowLocalBinding ?? false,
      allowAllUnixSockets: options.allowAllUnixSockets ?? false,
      allowUnixSockets: unique(options.allowUnixSockets ?? []),
      ...(needsNetworkRestriction && options.httpProxyPort !== undefined
        ? { httpProxyPort: options.httpProxyPort }
        : {}),
      ...(needsNetworkRestriction && options.socksProxyPort !== undefined
        ? { socksProxyPort: options.socksProxyPort }
        : {}),
    },
    windows: {
      appContainerMode: 'lpac',
      allowLoopback: false,
    },
  }
}

function environmentAssignments(
  options: WrapCommandWithLandstripOptions,
): string[] {
  const assignments = generateProxyEnvVars(
    options.httpProxyPort,
    options.socksProxyPort,
    options.caCertPath,
    options.proxyAuthToken,
    options.writeConfig === undefined,
    encodeSandboxedCommand(options.commandId ?? options.command),
  )

  const javaToolOptions = buildJavaToolOptions({
    agentJarPath: options.javaAgentJarPath,
    flags:
      options.platform === 'macos' &&
      options.needsNetworkRestriction &&
      (options.allowLocalBinding ||
        options.httpProxyPort !== undefined ||
        options.socksProxyPort !== undefined)
        ? ['-Djava.net.preferIPv4Stack=true']
        : [],
    unsetEnvVars: [...(options.unsetEnvVars ?? [])],
    inherited: process.env.JAVA_TOOL_OPTIONS,
  })
  if (javaToolOptions !== undefined) {
    assignments.push(`JAVA_TOOL_OPTIONS=${javaToolOptions}`)
  }

  if (options.gitSafeDirectories?.length) {
    const git = buildPosixGitSafeDirEnv({
      safeDirs: options.gitSafeDirectories,
      unsetEnvVars: options.unsetEnvVars,
      setEnvVars: options.setEnvVars,
    })
    assignments.push(
      ...Object.entries(git).map(([name, value]) => `${name}=${value}`),
    )
  }
  return assignments
}

export function wrapCommandWithLandstrip(
  options: WrapCommandWithLandstripOptions,
): LandstripInvocation {
  const policyPath = writeLandstripPolicy(buildLandstripPolicy(options))
  try {
    const landstripArgs = [
      options.landstripPath,
      'run',
      '-p',
      policyPath,
      '--',
      options.shell.exe,
      ...options.shell.args,
      options.command,
    ]
    const unset = (options.unsetEnvVars ?? []).flatMap(name => ['-u', name])
    const set = Object.entries(options.setEnvVars ?? {}).map(
      ([name, value]) => `${name}=${value}`,
    )
    return {
      argv: [
        'env',
        ...unset,
        ...set,
        ...environmentAssignments(options),
        ...landstripArgs,
      ],
      env: process.env,
      policyPath,
    }
  } catch (error) {
    rmSync(policyPath, { force: true })
    throw error
  }
}

export function quoteLandstripInvocation(
  invocation: LandstripInvocation,
): string {
  return quote(invocation.argv)
}
