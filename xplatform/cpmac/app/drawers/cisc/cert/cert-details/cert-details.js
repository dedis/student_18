const FrameModule = require("ui/frame");
const ObservableArray = require("data/observable-array").ObservableArray;
const ObservableModule = require("data/observable");
const topmost = require("ui/frame").topmost;
const merge = require("node.extend");
const common = require("asn1js/org/pkijs/common");
const _asn1js = require("asn1js");
const _pkijs = require("pkijs");
const _x509schema = require("pkijs/org/pkijs/x509_schema");
const pki = require('node-forge').pki;
const Dialog = require("ui/dialogs");

const caCert = "-----BEGIN CERTIFICATE-----\
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\
-----END CERTIFICATE-----";


let viewModel = ObservableModule.fromObject({
	certName: "",
    certInfos: new ObservableArray()
});

let certStored;

function onNavigatingTo(args) {
  	if (args.isBackNavigation) {
        return;
    }

    page = args.object;

    const context = page.navigationContext;
    certStored = context.cert;
    const result = getBasicInfo(certStored);

    page.bindingContext = viewModel

    viewModel.certName = result.subject;
    if(viewModel.certInfos.length == 0){
       loadCertInfos(result)
    }
}

function verifyCert(args){

    const cert = pki.certificateFromPem(certStored);
    caStore = pki.createCaStore([ caCert ]);

    try {
        pki.verifyCertificateChain(caStore, [cert]);
    } catch (e) {
        return Dialog.alert({
            title: "Verify",
            message: "Certificate is not valid",
            okButtonText: "Ok"
        })
    }
    return Dialog.alert({
            title: "Verify",
            message: "Certificate is valid",
            okButtonText: "Ok"
    })
}

function loadCertInfos(certInfos){

    viewModel.certInfos.push(ObservableModule.fromObject({
        certInfoTitle: "Subject",
        certInfo: certInfos.subject
    }));
    viewModel.certInfos.push(ObservableModule.fromObject({
        certInfoTitle: "Altnames",
        certInfo: certInfos.altnames.join(", ")
    }));
    viewModel.certInfos.push(ObservableModule.fromObject({
        certInfoTitle: "Issued at",
        certInfo: certInfos._issuedAt
    }));
    viewModel.certInfos.push(ObservableModule.fromObject({
        certInfoTitle: "Expires at",
        certInfo: certInfos._expiresAt
    }));
}

function pemToBinAb(pem) {
    var b64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
    var buf = Buffer.from(b64, 'base64');
    var ab = new Uint8Array(buf).buffer;
    return ab;
}

function getCertInfo(pem) {
    var ab = pemToBinAb(pem);

    // #region Merging function/object declarations for ASN1js and PKIjs
    var asn1js = merge(true, _asn1js, common);

    var x509schema = merge(true, _x509schema, asn1js);

    var pkijs_1 = merge(true, _pkijs, asn1js);
    var pkijs = merge(true, pkijs_1, x509schema);

    var asn1 = pkijs.org.pkijs.fromBER(ab);
    var certSimpl = new pkijs.org.pkijs.simpl.CERT({ schema: asn1.result });

    return certSimpl;
}

function getBasicInfo(pem) {
    var c = getCertInfo(pem);
    var domains = [];
    var sub;

    c.extensions.forEach(function (ext) {
        if (ext.parsedValue && ext.parsedValue.altNames) {
                ext.parsedValue.altNames.forEach(function (alt) {
                domains.push(alt.Name);
            });
        }
    });

    sub = c.subject.types_and_values[0].value.value_block.value || null;

    return {
        subject: sub
        , altnames: domains
        , _issuedAt: c.notBefore.value
        , _expiresAt: c.notAfter.value
        , issuedAt: new Date(c.notBefore.value).valueOf()
        , expiresAt: new Date(c.notAfter.value).valueOf()
    };
}

function onDrawerButtonTap(args) {
    const sideDrawer = FrameModule.topmost().getViewById("sideDrawer");
    sideDrawer.showDrawer();
}

function goBack() {
    topmost().goBack();
}

exports.goBack = goBack;
exports.verifyCert = verifyCert;
exports.onNavigatingTo = onNavigatingTo;
exports.onDrawerButtonTap = onDrawerButtonTap;
