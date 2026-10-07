/**
 * XML - WS-Discovery on UDP 3702 - against the reference, row for row.
 *
 *   npx tsx scripts/xml/dissect.ts
 *
 * Every Windows machine looks for printers, scanners and media devices with
 * SOAP-over-UDP to 239.255.255.250:3702, and devices answer the same way. The
 * reference shows it as `UDP/XML` with the document drawn as written: each
 * tag a row, its attributes beneath it with the last one carrying the `>`,
 * its text, and the closing tag. The cases are the messages WS-Discovery
 * sends - Probe, ProbeMatches, Hello, Bye - and the markup that is easy to
 * get subtly wrong: a self-closing tag with attributes, single quotes, a
 * comment, CDATA, text either side of a child, entities left as written,
 * a document cut short, and a payload that is not XML at all.
 */
import { Bytes, udpFrame } from '../parity/synthetic';
import { checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const ascii = (text: string) => new Bytes().ascii(text).build();
const ENVELOPE = 'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
  + 'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
  + 'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"';
const soap = (action: string, body: string) => '<?xml version="1.0" encoding="utf-8"?>'
  + `<soap:Envelope ${ENVELOPE}><soap:Header>`
  + '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
  + `<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/${action}</wsa:Action>`
  + '<wsa:MessageID>urn:uuid:6a3c2b1e-0d4f-4b8a-9e2f-1c5d7e9a0b3c</wsa:MessageID>'
  + `</soap:Header><soap:Body>${body}</soap:Body></soap:Envelope>`;

const cases: OracleCase[] = [
  { label: 'a Probe for devices', frame: udpFrame(50000, 3702, ascii(soap('Probe',
    '<wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>'))) },
  { label: 'a ProbeMatches answer', frame: udpFrame(3702, 50000, ascii(soap('ProbeMatches',
    '<wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:0001</wsa:Address>'
    + '</wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types>'
    + '<wsd:XAddrs>http://192.0.2.2:5357/0001/</wsd:XAddrs><wsd:MetadataVersion>2</wsd:MetadataVersion>'
    + '</wsd:ProbeMatch></wsd:ProbeMatches>'))) },
  { label: 'a Hello, indented with CRLF', frame: udpFrame(3702, 3702, ascii(
    '<?xml version="1.0" encoding="utf-8"?>\r\n<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">\r\n'
    + '  <soap:Body>\r\n    <wsd:Hello/>\r\n  </soap:Body>\r\n</soap:Envelope>\r\n')) },
  { label: 'a Bye with an AppSequence', frame: udpFrame(3702, 3702, ascii(soap('Bye',
    '<wsd:AppSequence InstanceId="1" MessageNumber="12"/><wsd:Bye/>'))) },
  { label: 'self-closing attributes, quotes, comment, CDATA, mixed text, entities', frame: udpFrame(50000, 3702, ascii(
    '<a x="1" y=\'2\'/><!-- note here --><b>  some text  </b><c><![CDATA[raw <stuff>]]></c>'
    + '<d>t1<e/>t2</d><f a="&amp;" b="x > y"/>')) },
  { label: 'a declaration, a doctype and tabs', frame: udpFrame(50000, 3702, ascii(
    '<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE html>\n<root xmlns="urn:x">\n\t<item id="7">hello world</item>\n</root>')) },
  { label: 'a document cut short', frame: udpFrame(50000, 3702, ascii('<a>unclosed <b>')) },
  { label: 'a payload that is not XML', frame: udpFrame(50000, 3702, ascii('not xml at all')) },
];

await compareWithReference(cases, { rows: /^xml\./ });
await checkRevisit(cases);
finish('XML');
