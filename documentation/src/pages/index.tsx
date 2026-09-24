import type { ReactNode } from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Heading from '@theme/Heading';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';

import styles from './index.module.css';

interface Destination {
    title: string;
    description: string;
    to: string;
}

const destinations: Destination[] = [
    {
        title: 'User Documentation',
        description:
            'Put a program in the sandbox, write a policy for it and understand what Phobos does and does not protect against.',
        to: '/user/phobos/what-is-phobos',
    },
    {
        title: 'Contributor Documentation',
        description:
            'The technologies Phobos is built on, the policy model and the subsystems. For people working on Phobos itself.',
        to: '/contributor/how-can-you-contribute',
    },
];

const features: string[] = [
    'A filesystem boundary enforced by Landlock, with no privilege and no container flag',
    'An outbound allow-list supervised by a seccomp connect guard, by address and port',
    'Host names enforced by an egress broker that reads the Transport Layer Security host name',
    'A wall-clock timeout nothing under it can step out of',
    'Self-imposed resource limits on memory, processes, open files, file size and processor time',
    'A discovery phase that measures what a program needs instead of guessing',
];

function Hero(): ReactNode {
    const { siteConfig } = useDocusaurusContext();

    return (
        <header className={styles.hero}>
            <div className="container">
                <Heading as="h1" className={styles.heroTitle}>
                    Phobos
                </Heading>
                <p className={styles.heroSubtitle}>{siteConfig.tagline}</p>
                <p className={styles.heroPitch}>
                    You have to run a program you do not trust, and you do not know what it would
                    reach for if you let it? Phobos measures what the program needs, then permits
                    exactly that and denies the rest.
                </p>
            </div>
        </header>
    );
}

export default function Home(): ReactNode {
    return (
        <Layout
            title="Phobos"
            description="Documentation for Phobos: run any program with only the filesystem, network and resource access it was shown to need."
        >
            <Hero />
            <main className="container">
                <div className={styles.cards}>
                    {destinations.map((destination) => (
                        <Link key={destination.to} to={destination.to} className={styles.card}>
                            <Heading as="h2" className={styles.cardTitle}>
                                {destination.title}
                            </Heading>
                            <p className={styles.cardDescription}>{destination.description}</p>
                        </Link>
                    ))}
                </div>

                <div className={clsx('row', styles.features)}>
                    <div className="col col--6">
                        <Heading as="h2">What Phobos does</Heading>
                        <ul>
                            {features.map((feature) => (
                                <li key={feature}>{feature}</li>
                            ))}
                        </ul>
                    </div>
                    <div className="col col--6">
                        <Heading as="h2">Put a command in the sandbox</Heading>
                        <CodeBlock language="bash" title="inside the run-phase image">
                            {`\${PHOBOS_HOME}/phobos.sh --config exercise.cfg -- ./gradlew test`}
                        </CodeBlock>
                        <CodeBlock language="ini" title="exercise.cfg">
                            {`[read]
/srv/data

[connect]
allow 192.0.2.10:443

[limits]
timeout=120
mem_mb=2048`}
                        </CodeBlock>
                    </div>
                </div>
            </main>
        </Layout>
    );
}
