/**
 * Business-wide details, kept in step with the main site's
 * client-lexiphanic-co-uk/src/content/site/settings.json so the header, footer
 * and report cover match lexiphanic.co.uk.
 */
export const site = {
  name: "Lexiphanic",
  legalName: "Lexiphanic Limited",
  companyNumber: "10065854",
  tagline: "Bespoke websites & online growth",
  description:
    "Lexiphanic builds bespoke websites that help you grow your business online.",
  url: "https://www.lexiphanic.co.uk",
  email: "hello@lexiphanic.co.uk",
  phone: "+447915810750",
  phoneDisplay: "07915 810 750",
  address: {
    street: "650 Anlaby Road",
    locality: "Kingston Upon Hull",
    region: "East Yorkshire",
    postcode: "HU3 6UU",
    country: "United Kingdom",
  },
  social: {
    linkedin: "https://uk.linkedin.com/in/happypaul55",
  },
  companyUrl:
    "https://find-and-update.company-information.service.gov.uk/company/10065854",
  app: {
    name: "Audit",
    fullName: "Lexiphanic Audit",
    url: "https://audit.lexiphanic.co.uk",
  },
  pricing: {
    currency: "GBP",
    setup: "£25",
    setupValue: "25.00",
    monthly: "£8.50",
    monthlyValue: "8.50",
    setupDescription: "One-off setup fee",
    note: "Based on one .co.uk domain, paid up-front for the year.",
  },
} as const;

export const addressLines = [
  site.address.street,
  site.address.locality,
  `${site.address.region}, ${site.address.postcode}`,
  site.address.country,
];

export const auditTagline = "Website audit";
export const auditDescription =
  "A free, evidence-based snapshot of the site you have today: HTTPS and certificates, www/apex redirects, metadata, HSTS, llms.txt, security.txt, well-known files, security headers, performance and the platform behind it.";
