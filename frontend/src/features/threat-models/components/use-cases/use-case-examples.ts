/**
 * Example text for the use case and abuse case forms, shown as placeholders.
 * One running example (an online shop), so the fields read as one story: the
 * use case "Place an order" and its abuse case "Card testing at checkout".
 * An abuse case's steps mirror the use case's steps; it is misuse of the
 * feature in the use case's own terms, not the attacker's wider operation.
 */

export const USE_CASE_EXAMPLES = {
  name: 'e.g. Place an order',
  description: 'e.g. A signed-in customer buys the items in their cart and pays by card.',
  mainFlow: ['e.g. Add items to the cart', 'e.g. Enter payment details', 'e.g. Submit the order'],
  preconditions: ['e.g. The customer is signed in', 'e.g. The cart is not empty'],
  postconditions: ['e.g. The order is stored and the card is charged', 'e.g. The customer gets a confirmation email'],
  successCriteria: ["e.g. The order shows in the customer's order history"],
  alternativeFlow: {
    name: 'e.g. Pay with a saved card',
    condition: 'e.g. The customer has a saved card',
    description: 'e.g. Skips entering payment details',
    steps: ['e.g. Pick the saved card', 'e.g. Submit the order'],
  },
  exception: {
    name: 'e.g. Card declined',
    condition: 'e.g. The payment provider declines the card',
    description: 'e.g. The order cannot be paid',
    handling: 'e.g. Show the decline reason and keep the cart',
  },
}

export const ABUSE_CASE_EXAMPLES = {
  name: 'e.g. Card testing at checkout',
  description: 'e.g. A fraudster tests stolen card numbers by placing small orders until one goes through.',
  preconditions: ['e.g. The actor has card numbers that are not theirs'],
  mainFlow: [
    'e.g. Add a low-value item to the cart',
    "e.g. Enter card details that are not the actor's",
    'e.g. Submit, and repeat at a volume no real customer would',
  ],
  detectionOpportunities: [
    'e.g. Many declined payments from one account or address',
    'e.g. Many small orders in a short time',
  ],
}

/** What an abuse case is, and how it relates to threats. */
export const ABUSE_CASE_HELP =
  "An abuse case is how an attacker misuses this use case, step by step, in the use case's own terms. " +
  'Link the threats it leads to; you rate those and add countermeasures.'

/** The placeholder for row `index`: its own example, else the last one's hint. */
export function placeholderFor(placeholders: string[] | undefined, index: number, fallback?: string): string | undefined {
  if (placeholders && index < placeholders.length) return placeholders[index]
  return fallback
}
