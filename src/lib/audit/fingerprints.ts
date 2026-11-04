export type FingerprintConfidence = "high" | "medium" | "low";

export interface Fingerprint {
  name: string;
  category: string;
  confidence: FingerprintConfidence;
}

interface Rule {
  name: string;
  category: string;
  patterns: RegExp[];
  confidence?: FingerprintConfidence;
}

const platforms: Rule[] = [
  { name: "WordPress", category: "CMS", patterns: [/wp-content\//i, /wp-includes\//i, /wp-json\//i], confidence: "high" },
  { name: "WooCommerce", category: "Ecommerce", patterns: [/woocommerce/i, /wc-block/i, /wc_add_to_cart/i], confidence: "high" },
  { name: "Shopify", category: "Ecommerce", patterns: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /shopify-payment/i], confidence: "high" },
  { name: "Wix", category: "Website builder", patterns: [/wixstatic\.com/i, /parastorage\.com/i, /wix\.com/i], confidence: "high" },
  { name: "Squarespace", category: "Website builder", patterns: [/static1\.squarespace\.com/i, /squarespace\.com/i], confidence: "high" },
  { name: "Webflow", category: "Website builder", patterns: [/data-wf-site/i, /webflow\.js/i, /webflow\.com/i], confidence: "high" },
  { name: "Framer", category: "Website builder", patterns: [/framerusercontent\.com/i, /framer\.com/i], confidence: "medium" },
  { name: "GoDaddy Website Builder", category: "Website builder", patterns: [/godaddy/i, /websitebuilder/i], confidence: "medium" },
  { name: "Duda", category: "Website builder", patterns: [/dudamobile/i, /dudaone/i, /duda\.co/i], confidence: "medium" },
  { name: "Ghost", category: "CMS", patterns: [/ghost-url/i, /ghost\.org/i, /content\/images\/.*ghost/i], confidence: "medium" },
  { name: "HubSpot CMS", category: "CMS", patterns: [/hs_cos_wrapper/i, /hs-scripts\.com/i], confidence: "medium" },
  { name: "Joomla", category: "CMS", patterns: [/joomla/i, /com_content/i], confidence: "medium" },
  { name: "Drupal", category: "CMS", patterns: [/drupal/i, /sites\/default\/files/i], confidence: "medium" },
  { name: "Magento", category: "Ecommerce", patterns: [/magento/i, /mage\/cookies/i, /static\/version/i], confidence: "medium" },
  { name: "Adobe Commerce", category: "Ecommerce", patterns: [/adobe commerce/i, /magento/i], confidence: "low" },
  { name: "BigCommerce", category: "Ecommerce", patterns: [/bigcommerce\.com/i, /bc-sf-filter/i], confidence: "medium" },
  { name: "PrestaShop", category: "Ecommerce", patterns: [/prestashop/i], confidence: "medium" },
  { name: "OpenCart", category: "Ecommerce", patterns: [/catalog\/view\/theme/i, /index\.php\?route=/i], confidence: "medium" },
  { name: "Shopware", category: "Ecommerce", patterns: [/shopware/i], confidence: "medium" },
  { name: "Salesforce Commerce Cloud", category: "Ecommerce", patterns: [/demandware/i, /salesforce commerce/i], confidence: "medium" },
  { name: "Craft CMS", category: "CMS", patterns: [/craftcms/i, /cpresources\//i], confidence: "medium" },
  { name: "ExpressionEngine", category: "CMS", patterns: [/expressionengine/i], confidence: "medium" },
  { name: "TYPO3", category: "CMS", patterns: [/typo3/i], confidence: "medium" },
  { name: "Umbraco", category: "CMS", patterns: [/umbraco/i], confidence: "medium" },
  { name: "Sitecore", category: "CMS", patterns: [/sitecore/i], confidence: "medium" },
  { name: "Kentico", category: "CMS", patterns: [/kentico/i], confidence: "medium" },
  { name: "Contentful", category: "CMS", patterns: [/ctfassets\.net/i, /contentful/i], confidence: "medium" },
  { name: "Sanity", category: "CMS", patterns: [/cdn\.sanity\.io/i, /sanity\.io/i], confidence: "medium" },
  { name: "Strapi", category: "CMS", patterns: [/strapi/i], confidence: "medium" },
  { name: "Payload CMS", category: "CMS", patterns: [/payloadcms/i], confidence: "medium" },
  { name: "Statamic", category: "CMS", patterns: [/statamic/i], confidence: "medium" },
  { name: "Grav", category: "CMS", patterns: [/grav\.org/i, /user\/themes\/antimatter/i], confidence: "medium" },
  { name: "October CMS", category: "CMS", patterns: [/octobercms/i, /modules\/system\/assets/i], confidence: "medium" },
  { name: "MODX", category: "CMS", patterns: [/modx/i], confidence: "medium" },
  { name: "SilverStripe", category: "CMS", patterns: [/silverstripe/i], confidence: "medium" },
  { name: "ProcessWire", category: "CMS", patterns: [/processwire/i], confidence: "medium" },
  { name: "Concrete CMS", category: "CMS", patterns: [/concrete5/i, /concretecms/i], confidence: "medium" },
  { name: "Bitrix", category: "CMS", patterns: [/bitrix/i], confidence: "medium" },
  { name: "Webnode", category: "Website builder", patterns: [/webnode/i], confidence: "medium" },
  { name: "Jimdo", category: "Website builder", patterns: [/jimdo/i], confidence: "medium" },
  { name: "Weebly", category: "Website builder", patterns: [/weebly/i], confidence: "medium" },
  { name: "Strikingly", category: "Website builder", patterns: [/strikingly/i], confidence: "medium" },
  { name: "Carrd", category: "Website builder", patterns: [/carrd\.co/i], confidence: "medium" },
  { name: "Bubble", category: "Website builder", patterns: [/bubble\.io/i], confidence: "medium" },
  { name: "Softr", category: "Website builder", patterns: [/softr\.io/i], confidence: "medium" },
  { name: "Odoo", category: "CMS", patterns: [/odoo/i], confidence: "medium" },
  { name: "Adobe Experience Manager", category: "CMS", patterns: [/etc\.clientlibs/i, /content\/dam\//i, /aem/i], confidence: "medium" },
  { name: "Shoplazza", category: "Ecommerce", patterns: [/shoplazza/i], confidence: "medium" },
  { name: "Shopline", category: "Ecommerce", patterns: [/shopline/i], confidence: "medium" },
  { name: "Ecwid", category: "Ecommerce", patterns: [/ecwid/i], confidence: "medium" },
  { name: "Volusion", category: "Ecommerce", patterns: [/volusion/i], confidence: "medium" },
  { name: "Shift4Shop", category: "Ecommerce", patterns: [/3dcart/i, /shift4shop/i], confidence: "medium" },
  { name: "Zen Cart", category: "Ecommerce", patterns: [/zen cart/i, /zen-cart/i], confidence: "medium" },
  { name: "CS-Cart", category: "Ecommerce", patterns: [/cs-cart/i], confidence: "medium" },
  { name: "osCommerce", category: "Ecommerce", patterns: [/oscommerce/i], confidence: "medium" },
];

const frameworks: Rule[] = [
  { name: "Next.js", category: "Framework", patterns: [/__NEXT_DATA__/, /\/_next\/static\//], confidence: "high" },
  { name: "Nuxt", category: "Framework", patterns: [/__NUXT__/, /\/_nuxt\//], confidence: "high" },
  { name: "Remix", category: "Framework", patterns: [/__remixContext/, /remix\.run/], confidence: "high" },
  { name: "Gatsby", category: "Framework", patterns: [/___gatsby/, /gatsby\.js/], confidence: "high" },
  { name: "SvelteKit", category: "Framework", patterns: [/__sveltekit/, /sveltekit/i], confidence: "high" },
  { name: "Astro", category: "Framework", patterns: [/astro-island/, /data-astro-cid/, /\/_astro\//, /astro\.build/], confidence: "high" },
  { name: "Angular", category: "Framework", patterns: [/ng-version=/, /angular(?:\.min)?\.js/i], confidence: "high" },
  { name: "React", category: "Framework", patterns: [/data-reactroot/i, /react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Vue", category: "Framework", patterns: [/data-v-[a-f0-9]{6,}/i, /vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Ember", category: "Framework", patterns: [/ember(?:\.min)?\.js/i, /ember-cli/i], confidence: "medium" },
  { name: "Backbone", category: "Framework", patterns: [/backbone(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Alpine.js", category: "Framework", patterns: [/x-data=/i, /alpinejs/i], confidence: "medium" },
  { name: "HTMX", category: "Framework", patterns: [/hx-get=/i, /htmx(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Laravel", category: "Framework", patterns: [/laravel/i, /XSRF-TOKEN/i, /livewire/i], confidence: "medium" },
  { name: "Django", category: "Framework", patterns: [/csrfmiddlewaretoken/i, /django/i], confidence: "medium" },
  { name: "Ruby on Rails", category: "Framework", patterns: [/csrf-token/i, /rails/i], confidence: "low" },
  { name: "Symfony", category: "Framework", patterns: [/symfony/i], confidence: "medium" },
  { name: "CodeIgniter", category: "Framework", patterns: [/codeigniter/i], confidence: "medium" },
  { name: "ASP.NET", category: "Framework", patterns: [/__VIEWSTATE/i, /asp\.net/i], confidence: "high" },
  { name: "PHP", category: "Language", patterns: [/x-powered-by:\s*php/i, /\.php(?:[?"']|$)/i], confidence: "high" },
  { name: "Node.js", category: "Language", patterns: [/x-powered-by:\s*express/i, /node\.js/i], confidence: "medium" },
  { name: "Java", category: "Language", patterns: [/jsessionid/i, /x-powered-by:\s*servlet/i], confidence: "medium" },
];

const analytics: Rule[] = [
  { name: "Google Analytics 4", category: "Analytics", patterns: [/googletagmanager\.com\/gtag\/js\?id=G-/i, /gtag\(['"]config['"],\s*['"]G-/i], confidence: "high" },
  { name: "Google Analytics (UA)", category: "Analytics", patterns: [/UA-\d{4,}-\d+/], confidence: "medium" },
  { name: "Google Tag Manager", category: "Tag manager", patterns: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]+/], confidence: "high" },
  { name: "Meta Pixel", category: "Advertising", patterns: [/connect\.facebook\.net/i, /fbq\(/i], confidence: "high" },
  { name: "LinkedIn Insight", category: "Advertising", patterns: [/snap\.licdn\.com/i, /linkedin insight/i], confidence: "high" },
  { name: "TikTok Pixel", category: "Advertising", patterns: [/analytics\.tiktok\.com/i, /ttq\./i], confidence: "high" },
  { name: "Snap Pixel", category: "Advertising", patterns: [/sc-static\.net\/scevent/i, /snaptr\(/i], confidence: "high" },
  { name: "Pinterest Tag", category: "Advertising", patterns: [/ct\.pinterest\.com/i, /pintrk\(/i], confidence: "high" },
  { name: "Reddit Pixel", category: "Advertising", patterns: [/redditstatic\.com\/ads\/pixel/i, /rdt\(/i], confidence: "high" },
  { name: "X Pixel", category: "Advertising", patterns: [/static\.ads-twitter\.com/i, /twq\(/i], confidence: "high" },
  { name: "Hotjar", category: "Analytics", patterns: [/static\.hotjar\.com/i, /hj\(/i], confidence: "high" },
  { name: "Microsoft Clarity", category: "Analytics", patterns: [/clarity\.ms/i], confidence: "high" },
  { name: "FullStory", category: "Analytics", patterns: [/fullstory\.com/i], confidence: "high" },
  { name: "LogRocket", category: "Analytics", patterns: [/logrocket/i], confidence: "high" },
  { name: "Segment", category: "Analytics", patterns: [/cdn\.segment\.com/i, /analytics\.load/i], confidence: "high" },
  { name: "Mixpanel", category: "Analytics", patterns: [/mixpanel/i], confidence: "medium" },
  { name: "Amplitude", category: "Analytics", patterns: [/amplitude/i], confidence: "medium" },
  { name: "Heap", category: "Analytics", patterns: [/heap(?:\.js)?/i], confidence: "low" },
  { name: "Matomo", category: "Analytics", patterns: [/matomo|piwik/i], confidence: "medium" },
  { name: "Plausible", category: "Analytics", patterns: [/plausible\.io/i], confidence: "high" },
  { name: "Fathom", category: "Analytics", patterns: [/usefathom\.com/i], confidence: "high" },
  { name: "Simple Analytics", category: "Analytics", patterns: [/simpleanalytics/i], confidence: "high" },
  { name: "Umami", category: "Analytics", patterns: [/umami/i], confidence: "medium" },
  { name: "GoatCounter", category: "Analytics", patterns: [/goatcounter/i], confidence: "high" },
  { name: "Cloudflare Web Analytics", category: "Analytics", patterns: [/static\.cloudflareinsights\.com/i, /cloudflareinsights/i], confidence: "high" },
  { name: "Adobe Analytics", category: "Analytics", patterns: [/omtrdc\.net/i, /adobedtm\.com/i, /s_code/i], confidence: "medium" },
  { name: "Comscore", category: "Analytics", patterns: [/scorecardresearch\.com/i], confidence: "high" },
  { name: "Quantcast", category: "Analytics", patterns: [/quantserve\.com/i], confidence: "high" },
  { name: "Chartbeat", category: "Analytics", patterns: [/chartbeat/i], confidence: "high" },
  { name: "Parse.ly", category: "Analytics", patterns: [/parsely/i], confidence: "medium" },
  { name: "Yandex Metrica", category: "Analytics", patterns: [/mc\.yandex\.ru/i], confidence: "high" },
  { name: "Baidu Tongji", category: "Analytics", patterns: [/hm\.baidu\.com/i], confidence: "high" },
  { name: "Clicky", category: "Analytics", patterns: [/static\.getclicky\.com/i], confidence: "high" },
  { name: "Statcounter", category: "Analytics", patterns: [/statcounter\.com/i], confidence: "high" },
  { name: "Google Ads", category: "Advertising", patterns: [/googlesyndication\.com/i, /googleadservices\.com/i, /adsbygoogle/i], confidence: "high" },
  { name: "DoubleClick", category: "Advertising", patterns: [/doubleclick\.net/i], confidence: "high" },
  { name: "Amazon Ads", category: "Advertising", patterns: [/amazon-adsystem\.com/i], confidence: "high" },
  { name: "Criteo", category: "Advertising", patterns: [/criteo/i], confidence: "high" },
  { name: "Taboola", category: "Advertising", patterns: [/taboola/i], confidence: "high" },
  { name: "Outbrain", category: "Advertising", patterns: [/outbrain/i], confidence: "high" },
  { name: "The Trade Desk", category: "Advertising", patterns: [/adsrvr\.org/i], confidence: "high" },
  { name: "Bing Ads", category: "Advertising", patterns: [/bat\.bing\.com/i], confidence: "high" },
];

const consent: Rule[] = [
  { name: "OneTrust", category: "Consent", patterns: [/onetrust/i, /optanon/i], confidence: "high" },
  { name: "Cookiebot", category: "Consent", patterns: [/cookiebot/i], confidence: "high" },
  { name: "CookieYes", category: "Consent", patterns: [/cookieyes/i], confidence: "high" },
  { name: "Osano", category: "Consent", patterns: [/osano/i], confidence: "high" },
  { name: "Termly", category: "Consent", patterns: [/termly/i], confidence: "high" },
  { name: "iubenda", category: "Consent", patterns: [/iubenda/i], confidence: "high" },
  { name: "Complianz", category: "Consent", patterns: [/complianz/i], confidence: "high" },
  { name: "Borlabs", category: "Consent", patterns: [/borlabs/i], confidence: "high" },
  { name: "Usercentrics", category: "Consent", patterns: [/usercentrics/i], confidence: "high" },
  { name: "Quantcast Choice", category: "Consent", patterns: [/quantcast/i], confidence: "medium" },
  { name: "Didomi", category: "Consent", patterns: [/didomi/i], confidence: "high" },
  { name: "Sourcepoint", category: "Consent", patterns: [/sourcepoint/i], confidence: "high" },
  { name: "TrustArc", category: "Consent", patterns: [/trustarc/i], confidence: "high" },
  { name: "Cookie Information", category: "Consent", patterns: [/cookieinformation/i], confidence: "high" },
  { name: "Klaro", category: "Consent", patterns: [/klaro/i], confidence: "high" },
  { name: "CookieConsent", category: "Consent", patterns: [/cookieconsent/i], confidence: "medium" },
  { name: "Axeptio", category: "Consent", patterns: [/axeptio/i], confidence: "high" },
  { name: "Pandectes", category: "Consent", patterns: [/pandectes/i], confidence: "high" },
  { name: "Consentmanager", category: "Consent", patterns: [/consentmanager/i], confidence: "high" },
];

const chat: Rule[] = [
  { name: "Intercom", category: "Chat / support", patterns: [/intercom/i], confidence: "high" },
  { name: "Drift", category: "Chat / support", patterns: [/js\.drift(?:t)?\.com/i, /drift\.com/i], confidence: "high" },
  { name: "Crisp", category: "Chat / support", patterns: [/crisp\.chat/i], confidence: "high" },
  { name: "Tawk.to", category: "Chat / support", patterns: [/embed\.tawk\.to/i, /tawk\.to/i], confidence: "high" },
  { name: "LiveChat", category: "Chat / support", patterns: [/livechatinc\.com/i, /livechat\.com/i], confidence: "high" },
  { name: "Zendesk", category: "Chat / support", patterns: [/zdassets\.com/i, /zendesk/i], confidence: "medium" },
  { name: "Freshdesk", category: "Chat / support", patterns: [/freshdesk/i], confidence: "high" },
  { name: "Olark", category: "Chat / support", patterns: [/olark/i], confidence: "high" },
  { name: "Tidio", category: "Chat / support", patterns: [/tidio/i], confidence: "high" },
  { name: "Smartsupp", category: "Chat / support", patterns: [/smartsupp/i], confidence: "high" },
  { name: "Help Scout", category: "Chat / support", patterns: [/helpscout/i], confidence: "high" },
  { name: "Gorgias", category: "Chat / support", patterns: [/gorgias/i], confidence: "high" },
];

const marketing: Rule[] = [
  { name: "HubSpot", category: "CRM / marketing", patterns: [/hs-scripts\.com/i, /hubspot/i], confidence: "high" },
  { name: "Salesforce", category: "CRM / marketing", patterns: [/salesforce/i, /pardot/i], confidence: "medium" },
  { name: "Marketo", category: "CRM / marketing", patterns: [/marketo/i], confidence: "high" },
  { name: "Mailchimp", category: "Email marketing", patterns: [/chimpstatic\.com/i, /mailchimp/i], confidence: "high" },
  { name: "Klaviyo", category: "Email marketing", patterns: [/klaviyo/i], confidence: "high" },
  { name: "ActiveCampaign", category: "Email marketing", patterns: [/activehosted\.com/i, /activecampaign/i], confidence: "high" },
  { name: "ConvertKit", category: "Email marketing", patterns: [/convertkit/i], confidence: "high" },
  { name: "Drip", category: "Email marketing", patterns: [/drip\.com/i, /getdrip/i], confidence: "high" },
  { name: "Brevo", category: "Email marketing", patterns: [/brevo/i, /sendinblue/i], confidence: "high" },
  { name: "Constant Contact", category: "Email marketing", patterns: [/constantcontact/i], confidence: "high" },
  { name: "Omnisend", category: "Email marketing", patterns: [/omnisend/i], confidence: "high" },
  { name: "Attentive", category: "Marketing", patterns: [/attentive/i], confidence: "high" },
  { name: "Postscript", category: "Marketing", patterns: [/postscript/i], confidence: "high" },
  { name: "Yotpo", category: "Reviews", patterns: [/yotpo/i], confidence: "high" },
  { name: "Privy", category: "Marketing", patterns: [/privy/i], confidence: "high" },
  { name: "Justuno", category: "Marketing", patterns: [/justuno/i], confidence: "high" },
  { name: "OptinMonster", category: "Marketing", patterns: [/optinmonster/i], confidence: "high" },
  { name: "Sumo", category: "Marketing", patterns: [/sumo\.com/i, /sumome/i], confidence: "high" },
  { name: "Hello Bar", category: "Marketing", patterns: [/hellobar/i], confidence: "high" },
  { name: "Wisepops", category: "Marketing", patterns: [/wisepops/i], confidence: "high" },
];

const payments: Rule[] = [
  { name: "Stripe", category: "Payments", patterns: [/js\.stripe\.com/i, /stripe\.com\/v3/i], confidence: "high" },
  { name: "PayPal", category: "Payments", patterns: [/paypalobjects\.com/i, /paypal\.com\/sdk/i], confidence: "high" },
  { name: "Braintree", category: "Payments", patterns: [/braintree/i], confidence: "high" },
  { name: "Square", category: "Payments", patterns: [/squareup\.com/i, /js\.squareup\.com/i], confidence: "high" },
  { name: "Adyen", category: "Payments", patterns: [/adyen/i], confidence: "high" },
  { name: "Klarna", category: "Payments", patterns: [/klarna/i], confidence: "high" },
  { name: "Afterpay", category: "Payments", patterns: [/afterpay/i], confidence: "high" },
  { name: "Affirm", category: "Payments", patterns: [/affirm/i], confidence: "high" },
  { name: "Authorize.net", category: "Payments", patterns: [/authorize\.net/i], confidence: "high" },
  { name: "Worldpay", category: "Payments", patterns: [/worldpay/i], confidence: "high" },
  { name: "Sage Pay", category: "Payments", patterns: [/sagepay/i, /sage pay/i], confidence: "high" },
  { name: "GoCardless", category: "Payments", patterns: [/gocardless/i], confidence: "high" },
  { name: "Mollie", category: "Payments", patterns: [/mollie/i], confidence: "high" },
  { name: "Checkout.com", category: "Payments", patterns: [/checkout\.com/i], confidence: "high" },
  { name: "Razorpay", category: "Payments", patterns: [/razorpay/i], confidence: "high" },
  { name: "Paystack", category: "Payments", patterns: [/paystack/i], confidence: "high" },
  { name: "Flutterwave", category: "Payments", patterns: [/flutterwave/i], confidence: "high" },
];

const booking: Rule[] = [
  { name: "Calendly", category: "Booking", patterns: [/calendly/i], confidence: "high" },
  { name: "Acuity Scheduling", category: "Booking", patterns: [/acuityscheduling/i], confidence: "high" },
  { name: "Booksy", category: "Booking", patterns: [/booksy/i], confidence: "high" },
  { name: "SimplyBook.me", category: "Booking", patterns: [/simplybook/i], confidence: "high" },
  { name: "Fresha", category: "Booking", patterns: [/fresha/i], confidence: "high" },
  { name: "Setmore", category: "Booking", patterns: [/setmore/i], confidence: "high" },
  { name: "Mindbody", category: "Booking", patterns: [/mindbody/i], confidence: "high" },
  { name: "Vagaro", category: "Booking", patterns: [/vagaro/i], confidence: "high" },
  { name: "Timely", category: "Booking", patterns: [/gettimely/i], confidence: "high" },
  { name: "Amelia", category: "Booking", patterns: [/ameliabooking/i], confidence: "high" },
  { name: "Bookly", category: "Booking", patterns: [/bookly/i], confidence: "medium" },
  { name: "OpenTable", category: "Booking", patterns: [/opentable/i], confidence: "high" },
  { name: "Resy", category: "Booking", patterns: [/resy\.com/i], confidence: "high" },
  { name: "Tock", category: "Booking", patterns: [/exploretock/i], confidence: "high" },
  { name: "SevenRooms", category: "Booking", patterns: [/sevenrooms/i], confidence: "high" },
];

const reviews: Rule[] = [
  { name: "Trustpilot", category: "Reviews", patterns: [/trustpilot/i], confidence: "high" },
  { name: "Bazaarvoice", category: "Reviews", patterns: [/bazaarvoice/i], confidence: "high" },
  { name: "Reviews.io", category: "Reviews", patterns: [/reviews\.io/i], confidence: "high" },
  { name: "Feefo", category: "Reviews", patterns: [/feefo/i], confidence: "high" },
  { name: "Judge.me", category: "Reviews", patterns: [/judge\.me/i], confidence: "high" },
  { name: "Loox", category: "Reviews", patterns: [/loox/i], confidence: "high" },
  { name: "Stamped", category: "Reviews", patterns: [/stamped\.io/i], confidence: "high" },
  { name: "Okendo", category: "Reviews", patterns: [/okendo/i], confidence: "high" },
];

const video: Rule[] = [
  { name: "YouTube", category: "Video", patterns: [/youtube\.com\/embed/i, /youtu\.be\//i], confidence: "high" },
  { name: "Vimeo", category: "Video", patterns: [/player\.vimeo\.com/i, /vimeo\.com\/video/i], confidence: "high" },
  { name: "Wistia", category: "Video", patterns: [/wistia/i], confidence: "high" },
  { name: "Mux", category: "Video", patterns: [/mux\.com/i, /stream\.mux\.com/i], confidence: "high" },
  { name: "Brightcove", category: "Video", patterns: [/brightcove/i], confidence: "high" },
  { name: "JW Player", category: "Video", patterns: [/jwplayer/i], confidence: "high" },
];

const hosting: Rule[] = [
  { name: "Cloudflare", category: "Hosting / CDN", patterns: [/cf-ray:/i, /server:\s*cloudflare/i], confidence: "high" },
  { name: "Vercel", category: "Hosting / CDN", patterns: [/x-vercel-id:/i, /x-vercel-cache:/i], confidence: "high" },
  { name: "Netlify", category: "Hosting / CDN", patterns: [/x-nf-request-id:/i, /x-netlify-id:/i], confidence: "high" },
  { name: "Amazon CloudFront", category: "Hosting / CDN", patterns: [/x-amz-cf-id:/i, /x-amz-cf-pop:/i], confidence: "high" },
  { name: "Amazon S3", category: "Hosting / CDN", patterns: [/server:\s*amazons3/i], confidence: "high" },
  { name: "Fastly", category: "Hosting / CDN", patterns: [/x-fastly-request-id:/i, /x-served-by:/i], confidence: "high" },
  { name: "Akamai", category: "Hosting / CDN", patterns: [/x-akamai-transformed:/i, /akamai/i], confidence: "medium" },
  { name: "GitHub Pages", category: "Hosting / CDN", patterns: [/x-github-request-id:/i], confidence: "high" },
  { name: "GitLab Pages", category: "Hosting / CDN", patterns: [/gitlab-pages/i], confidence: "medium" },
  { name: "Render", category: "Hosting / CDN", patterns: [/x-render-origin-server:/i, /render\.com/i], confidence: "high" },
  { name: "Railway", category: "Hosting / CDN", patterns: [/x-railway-edge:/i, /railway\.app/i], confidence: "high" },
  { name: "Fly.io", category: "Hosting / CDN", patterns: [/fly-request-id:/i, /fly\.io/i], confidence: "high" },
  { name: "Heroku", category: "Hosting / CDN", patterns: [/via:\s*1\.1 vegur/i, /heroku/i], confidence: "medium" },
  { name: "Kinsta", category: "Hosting / CDN", patterns: [/kinsta/i], confidence: "high" },
  { name: "WP Engine", category: "Hosting / CDN", patterns: [/wp engine/i, /x-powered-by:\s*wp engine/i], confidence: "high" },
  { name: "SiteGround", category: "Hosting / CDN", patterns: [/siteground/i], confidence: "medium" },
  { name: "Bluehost", category: "Hosting / CDN", patterns: [/bluehost/i], confidence: "medium" },
  { name: "Hostinger", category: "Hosting / CDN", patterns: [/hostinger/i], confidence: "medium" },
  { name: "GoDaddy", category: "Hosting / CDN", patterns: [/godaddy/i], confidence: "medium" },
  { name: "Namecheap", category: "Hosting / CDN", patterns: [/namecheap/i], confidence: "medium" },
  { name: "123-reg", category: "Hosting / CDN", patterns: [/123-reg/i], confidence: "medium" },
  { name: "Krystal", category: "Hosting / CDN", patterns: [/krystal/i], confidence: "medium" },
  { name: "IONOS", category: "Hosting / CDN", patterns: [/ionos/i, /1&1/i], confidence: "medium" },
  { name: "OVH", category: "Hosting / CDN", patterns: [/ovh/i], confidence: "medium" },
  { name: "Hetzner", category: "Hosting / CDN", patterns: [/hetzner/i], confidence: "medium" },
  { name: "DigitalOcean", category: "Hosting / CDN", patterns: [/digitalocean/i], confidence: "medium" },
  { name: "Sucuri", category: "Security / WAF", patterns: [/x-sucuri-id:/i, /sucuri/i], confidence: "high" },
  { name: "Wordfence", category: "Security / WAF", patterns: [/wordfence/i, /wfvt_/i], confidence: "high" },
  { name: "Imperva", category: "Security / WAF", patterns: [/x-iinfo:/i, /imperva/i], confidence: "high" },
  { name: "AWS WAF", category: "Security / WAF", patterns: [/awselb/i, /x-amzn-waf/i], confidence: "medium" },
  { name: "StackPath", category: "Security / WAF", patterns: [/stackpath/i], confidence: "medium" },
  { name: "nginx", category: "Server", patterns: [/server:\s*nginx/i], confidence: "high" },
  { name: "Apache", category: "Server", patterns: [/server:\s*apache/i], confidence: "high" },
  { name: "IIS", category: "Server", patterns: [/server:\s*microsoft-iis/i], confidence: "high" },
  { name: "LiteSpeed", category: "Server", patterns: [/server:\s*litespeed/i], confidence: "high" },
  { name: "Caddy", category: "Server", patterns: [/server:\s*caddy/i], confidence: "high" },
  { name: "OpenResty", category: "Server", patterns: [/server:\s*openresty/i], confidence: "high" },
  { name: "Google Web Server", category: "Server", patterns: [/server:\s*gws/i], confidence: "high" },
  { name: "Envoy", category: "Server", patterns: [/server:\s*envoy/i], confidence: "high" },
];

const assets: Rule[] = [
  { name: "Google Fonts", category: "Fonts", patterns: [/fonts\.googleapis\.com/i, /fonts\.gstatic\.com/i], confidence: "high" },
  { name: "Adobe Fonts", category: "Fonts", patterns: [/use\.typekit\.net/i, /typekit/i], confidence: "high" },
  { name: "Font Awesome", category: "Fonts", patterns: [/fontawesome/i, /font-awesome/i], confidence: "high" },
  { name: "jQuery", category: "JavaScript library", patterns: [/jquery(?:-[\d.]+)?(?:\.min)?\.js/i], confidence: "high" },
  { name: "Bootstrap", category: "JavaScript library", patterns: [/bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)/i], confidence: "high" },
  { name: "Tailwind CSS", category: "JavaScript library", patterns: [/tailwind/i], confidence: "medium" },
  { name: "Lodash", category: "JavaScript library", patterns: [/lodash(?:\.min)?\.js/i], confidence: "high" },
  { name: "Moment.js", category: "JavaScript library", patterns: [/moment(?:\.min)?\.js/i], confidence: "high" },
  { name: "Day.js", category: "JavaScript library", patterns: [/dayjs(?:\.min)?\.js/i], confidence: "high" },
  { name: "GSAP", category: "JavaScript library", patterns: [/gsap(?:\.min)?\.js/i], confidence: "high" },
  { name: "Swiper", category: "JavaScript library", patterns: [/swiper(?:\.min)?\.(?:js|css)/i], confidence: "high" },
  { name: "Slick", category: "JavaScript library", patterns: [/slick(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Owl Carousel", category: "JavaScript library", patterns: [/owl\.carousel/i], confidence: "high" },
  { name: "Lightbox", category: "JavaScript library", patterns: [/lightbox(?:\.min)?\.(?:js|css)/i], confidence: "medium" },
  { name: "Modernizr", category: "JavaScript library", patterns: [/modernizr/i], confidence: "high" },
  { name: "RequireJS", category: "JavaScript library", patterns: [/require(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Knockout", category: "JavaScript library", patterns: [/knockout(?:\.min)?\.js/i], confidence: "high" },
  { name: "Handlebars", category: "JavaScript library", patterns: [/handlebars(?:\.min)?\.js/i], confidence: "high" },
  { name: "Axios", category: "JavaScript library", patterns: [/axios(?:\.min)?\.js/i], confidence: "high" },
  { name: "Chart.js", category: "JavaScript library", patterns: [/chart(?:\.min)?\.js/i], confidence: "medium" },
  { name: "D3.js", category: "JavaScript library", patterns: [/d3(?:\.min)?\.js/i], confidence: "medium" },
  { name: "Three.js", category: "JavaScript library", patterns: [/three(?:\.min)?\.js/i], confidence: "medium" },
];

const RULES: Rule[] = [
  ...platforms,
  ...frameworks,
  ...analytics,
  ...consent,
  ...chat,
  ...marketing,
  ...payments,
  ...booking,
  ...reviews,
  ...video,
  ...hosting,
  ...assets,
];

/** Detect technology fingerprints from markup, response headers and URLs. */
export function detectFingerprints(input: {
  html: string;
  headers: Record<string, string>;
  url: string;
}): Fingerprint[] {
  const haystack = `${input.html.slice(0, 500_000)}\n${Object.entries(input.headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n")}\n${input.url}`;

  const found = new Map<string, Fingerprint>();
  for (const rule of RULES) {
    if (found.has(rule.name)) continue;
    if (rule.patterns.some((pattern) => pattern.test(haystack))) {
      found.set(rule.name, {
        name: rule.name,
        category: rule.category,
        confidence: rule.confidence ?? "medium",
      });
    }
  }

  return [...found.values()].sort(
    (a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name),
  );
}
