/**
 * WinGet manifests for the desktop installer, as text.
 *
 * Pure on purpose (no `node:*`): `generate.ts` writes the files and
 * `contracts.ts` asserts the text. Nothing here is submitted anywhere; a
 * manifest that validates locally is not a live package.
 *
 * ## Schema version
 *
 * 1.12.0, the version Microsoft Learn's "Create your package manifest" page
 * shows as current and the one the installed client (1.29) validates. One
 * version for all three files: WinGet requires them to agree.
 *
 * ## What the manifest may and may not say
 *
 * - `ElevationRequirement: elevatesSelf`. `setup.iss` is `PrivilegesRequired=admin`
 *   and does not offer a per-user choice, so the installer's own manifest asks
 *   Windows for the UAC prompt; WinGet is told not to elevate it and to warn.
 * - Extra switches go in `Custom`, which WinGet appends to its Inno defaults
 *   (`/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` for `--silent`,
 *   `/SP- /SILENT ...` for progress). Putting them in `Silent` would replace
 *   those defaults and repeat `/NORESTART`, so only the two switches WinGet
 *   does not add are written here.
 * - Return codes: 3010 (configured by `/RESTARTEXITCODE`) is a restart to
 *   finish, 8 a restart before install can proceed, 2 and 5 the user cancelled.
 *   No other nonzero code is declared a success.
 * - `Commands: [inwire]` names the launcher the installer puts on PATH. WinGet
 *   does not edit PATH itself and a terminal opened before the install will not
 *   see it. Nothing here says WinGet starts the app.
 */

/**
 * The Uninstall key `setup.iss` registers. `AppId={{GUID}}`: Inno reads `{{` as
 * an escaped brace and keeps the lone closing braces, so the name ends `}}_is1`.
 * `contracts.ts` derives it from `setup.iss` and fails if this drifts.
 */
export const DESKTOP_PRODUCT_CODE = '{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1';

export const WINGET_MANIFEST_VERSION = '1.12.0';

/**
 * A YAML double-quoted scalar. JSON string syntax is a subset of YAML 1.2
 * double-quoted syntax, so `JSON.stringify` quotes colons, `#`, leading dashes,
 * newlines, backslashes and non-ASCII safely, and a bare `yes` or `0123` can
 * never be read as another type. Every string value goes through here.
 */
export function yamlString(value: string): string {
  return JSON.stringify(value);
}

export type WingetFile = { name: string; text: string };

export type WingetInput = {
  packageId: string;
  version: string;
  url: string;
  /** Any case; written uppercase, the way `winget hash` prints it. */
  sha256: string;
};

const SWITCHES = '/RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS';

const RETURN_CODES: readonly (readonly [number, string])[] = [
  [2, 'cancelledByUser'],
  [5, 'cancelledByUser'],
  [8, 'rebootRequiredForInstall'],
  [3010, 'rebootRequiredToFinish'],
];

export function renderWingetManifests(input: WingetInput): WingetFile[] {
  const q = yamlString;
  const head = (type: string): string[] => [
    `PackageIdentifier: ${q(input.packageId)}`,
    `PackageVersion: ${q(input.version)}`,
  ].concat(type === 'version' ? [`DefaultLocale: ${q('en-US')}`] : []);
  const tail = (type: string): string[] => [
    `ManifestType: ${q(type)}`,
    `ManifestVersion: ${q(WINGET_MANIFEST_VERSION)}`,
  ];
  // The header is a comment (an editor hint) that `winget validate` asks for.
  const join = (type: string, lines: string[]): string =>
    `# yaml-language-server: $schema=https://aka.ms/winget-manifest.${type}.${WINGET_MANIFEST_VERSION}.schema.json\n${lines.join('\n')}\n`;

  const version = join('version', [...head('version'), ...tail('version')]);

  const installer = join('installer', [
    ...head('installer'),
    `InstallerType: ${q('inno')}`,
    `Scope: ${q('machine')}`,
    `ElevationRequirement: ${q('elevatesSelf')}`,
    `UpgradeBehavior: ${q('install')}`,
    'Commands:',
    `  - ${q('inwire')}`,
    'InstallerSwitches:',
    `  Custom: ${q(SWITCHES)}`,
    'ExpectedReturnCodes:',
    ...RETURN_CODES.flatMap(([code, response]) => [
      `  - InstallerReturnCode: ${code}`,
      `    ReturnResponse: ${q(response)}`,
    ]),
    `ProductCode: ${q(DESKTOP_PRODUCT_CODE)}`,
    'AppsAndFeaturesEntries:',
    `  - ProductCode: ${q(DESKTOP_PRODUCT_CODE)}`,
    `    DisplayVersion: ${q(input.version)}`,
    `    Publisher: ${q('Inwire')}`,
    'Installers:',
    `  - Architecture: ${q('x64')}`,
    `    InstallerUrl: ${q(input.url)}`,
    `    InstallerSha256: ${q(input.sha256.toUpperCase())}`,
    ...tail('installer'),
  ]);

  const locale = join('defaultLocale', [
    ...head('locale'),
    `PackageLocale: ${q('en-US')}`,
    `Publisher: ${q('Inwire')}`,
    `PackageName: ${q('Inwire')}`,
    `License: ${q('MIT')}`,
    `ShortDescription: ${q('A Windows packet analyzer. Capture and analysis are local; no account is needed.')}`,
    'Tags:',
    `  - ${q('packet-analyzer')}`,
    `  - ${q('network')}`,
    `  - ${q('pcap')}`,
    ...tail('defaultLocale'),
  ]);

  return [
    { name: `${input.packageId}.yaml`, text: version },
    { name: `${input.packageId}.installer.yaml`, text: installer },
    { name: `${input.packageId}.locale.en-US.yaml`, text: locale },
  ];
}
