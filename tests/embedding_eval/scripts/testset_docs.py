# Labelled documents for the embedding eval. Fictional owner: Jonas Becker, German, MSc student in Utrecht,
# Werkstudent for a Cologne company, family in Cologne. No real personal data.
# (id, lang, kind, text)

DOCS = [
# ---------------------------------------------------------------- rent, deposit
("kaution_rueck", "de", "mail", """Betreff: Rückzahlung Ihrer Mietkaution – Wohnung Venloer Str. 212, Köln-Ehrenfeld
Sehr geehrter Herr Becker,
nach der Wohnungsübergabe am 31. August habe ich die Wohnung geprüft. Für das Streichen des Flurs ziehe ich 180,00 € ab, wie im Übergabeprotokoll vermerkt. Die restliche Kaution von 1.450,00 € zuzüglich Zinsen überweise ich bis Ende des Monats auf Ihr Konto bei der ING. Die Nebenkostenabrechnung für das laufende Jahr folgt separat; dafür behalte ich keinen Betrag ein.
Mit freundlichen Grüßen
Klaus Hoffmann"""),
("kaution_konto", "de", "mail", """Betreff: Auflösung Ihres Mietkautionskontos Nr. 4410 228 913
Guten Tag Herr Becker,
Ihr Vermieter hat die Freigabe des verpfändeten Mietkautionskontos erteilt. Das Guthaben von 1.632,18 € (Einlage plus Zinsen) wird innerhalb von fünf Bankarbeitstagen auf Ihr Girokonto überwiesen. Das Kautionssparbuch wird anschließend geschlossen. Bitte bewahren Sie diese Nachricht für Ihre Unterlagen auf.
Ihre Sparkasse KölnBonn"""),
("borg_nl", "nl", "mail", """Onderwerp: Kamer Biltstraat 88 – borg en eerste maand huur
Hoi Jonas,
Leuk dat je de kamer neemt! Om de reservering definitief te maken moet je vóór 1 september de borg van € 1.100 en de eerste maand huur (€ 650) overmaken naar NL21 RABO 0123 4567 89 o.v.v. 'Biltstraat 88 kamer 3'. De borg krijg je terug binnen vier weken nadat je de sleutels hebt ingeleverd, mits de kamer netjes wordt achtergelaten. Het huurcontract stuur ik je morgen ter ondertekening.
Groet, Martijn van der Meer"""),
("huurcontract_nl", "nl", "pdf", """HUUROVEREENKOMST WOONRUIMTE – Biltstraat 88, Utrecht
Artikel 7 Waarborgsom
7.1 Huurder betaalt bij aanvang van de huur een waarborgsom ter hoogte van € 1.100, gelijk aan bijna twee maanden kale huur.
7.2 Verhuurder betaalt de waarborgsom uiterlijk 14 dagen na het einde van de huurovereenkomst terug, onder aftrek van eventuele kosten voor herstel van schade en achterstallige betalingen.
7.3 Over de waarborgsom wordt geen rente vergoed.
Artikel 8 Onderhoud
8.1 Klein onderhoud, zoals het vervangen van lampen en het ontstoppen van afvoeren, komt voor rekening van huurder."""),
("mietvertrag_de", "de", "pdf", """Mietvertrag über Wohnraum – Venloer Str. 212, 50823 Köln
§ 3 Mietdauer und Kündigung
(1) Das Mietverhältnis beginnt am 1. Oktober 2022 und läuft auf unbestimmte Zeit.
(2) Der Mieter kann das Mietverhältnis mit einer Frist von drei Monaten zum Monatsende kündigen. Die Kündigung bedarf der Schriftform.
§ 9 Schönheitsreparaturen
(1) Der Mieter übernimmt die Schönheitsreparaturen während der Mietzeit, soweit sie durch seinen Gebrauch erforderlich werden.
(2) Bei Auszug ist die Wohnung besenrein zu übergeben."""),
("mieterhoehung_de", "de", "letter", """Mieterhöhungsverlangen nach § 558 BGB
Sehr geehrter Herr Becker,
die Nettokaltmiete Ihrer Wohnung beträgt seit über 15 Monaten unverändert 610,00 €. Nach dem aktuellen Kölner Mietspiegel liegt die ortsübliche Vergleichsmiete für vergleichbare Wohnungen bei 11,40 € je Quadratmeter. Ich bitte Sie daher, einer Erhöhung der Miete auf 665,00 € ab dem 1. Februar zuzustimmen. Die Vorauszahlungen für Betriebskosten bleiben unverändert. Bitte senden Sie mir die beigefügte Zustimmungserklärung bis Ende Dezember zurück.
Klaus Hoffmann"""),
("huurverhoging_nl", "nl", "mail", """Onderwerp: Jaarlijkse huurverhoging per 1 juli
Beste huurder,
Hierbij informeren wij u over de jaarlijkse aanpassing van de huurprijs. Per 1 juli wordt de kale huur van uw kamer verhoogd met 4,1%, conform het maximale percentage dat de overheid dit jaar toestaat. Uw nieuwe maandhuur bedraagt € 676,65. Bent u het niet eens met deze verhoging, dan kunt u vóór 1 juli schriftelijk bezwaar maken; daarna kunt u naar de Huurcommissie.
Met vriendelijke groet,
Van der Meer Vastgoed"""),
("w_borg_chat", "nl", "whatsapp", """[WhatsApp – Sanne] Heb jij je borg al terug van je oude huisbaas? Ik wacht nu al zes weken op mijn geld van die kamer in Lombok en hij reageert niet op mijn mails.
[Jonas] Nee, nog niet, ze zeiden binnen vier weken... ik stuur morgen een herinnering.
[Sanne] Volgens het Juridisch Loket mag je na 14 dagen een ingebrekestelling sturen, ik doe dat vanavond."""),

# ---------------------------------------------------------------- tax
("steuerbescheid_de", "de", "letter", """Finanzamt Köln-West
Bescheid für 2025 über Einkommensteuer und Solidaritätszuschlag
Steuernummer 223/5112/0784
Die Einkommensteuer wird auf 1.204,00 € festgesetzt. Abzüglich der einbehaltenen Lohnsteuer von 1.816,00 € ergibt sich eine Erstattung von 612,00 €. Der Betrag wird auf das von Ihnen angegebene Konto überwiesen.
Rechtsbehelfsbelehrung: Gegen diesen Bescheid kann innerhalb eines Monats nach Bekanntgabe Einspruch eingelegt werden. Der Einspruch ist beim oben bezeichneten Finanzamt schriftlich einzureichen oder elektronisch zu übermitteln."""),
("steuer_elster_de", "de", "mail", """Betreff: ELSTER – Übermittlungsbestätigung
Ihre Einkommensteuererklärung 2025 wurde erfolgreich an das Finanzamt Köln-West übermittelt.
Transferticket: et2hj7k9q4mm
Eingang: 14.07.2026, 21:43 Uhr
Die Bearbeitung dauert erfahrungsgemäß einige Wochen. Den Steuerbescheid erhalten Sie per Post oder, falls Sie die Bescheiddatenübermittlung gewählt haben, zusätzlich in Ihrem ELSTER-Postfach. Bitte antworten Sie nicht auf diese automatisch erzeugte Nachricht."""),
("belasting_nl", "nl", "letter", """Belastingdienst
Uitnodiging om aangifte te doen – inkomstenbelasting 2025
Geachte heer Becker,
U moet aangifte inkomstenbelasting doen over 2025. Doe dit vóór 1 mei 2026 via Mijn Belastingdienst; u logt in met uw DigiD. Omdat u in 2025 in Nederland bent komen wonen, krijgt u een M-formulier voor het jaar van migratie. Lukt het niet om op tijd aangifte te doen, vraag dan uitstel aan. Te laat aangifte doen kan leiden tot een boete."""),
("toeslag_nl", "nl", "letter", """Dienst Toeslagen
Voorschotbeschikking zorgtoeslag 2026
U krijgt in 2026 een voorschot zorgtoeslag van € 123 per maand. Wij hebben dit berekend met een geschat toetsingsinkomen van € 18.400. Verandert uw inkomen of gaat u samenwonen? Geef dit dan direct door via Mijn toeslagen, anders moet u mogelijk geld terugbetalen. Het voorschot wordt rond de 20e van elke maand op uw rekening gestort."""),
("tax_advisor_en", "en", "mail", """Subject: Your 2025 returns – Germany and the Netherlands
Hi Jonas,
I went through your documents. Because you moved to Utrecht in February, you need to file in both countries for 2025. Your Werkstudent salary from the Cologne company stays taxable in Germany under the double taxation treaty, since you work for a German employer; the Dutch return then exempts it with progression. I have prepared the German return in ELSTER and the Dutch M form; please check the figures and sign before the end of April.
Best, Priya Raman"""),

# ---------------------------------------------------------------- electricity, utilities
("strom_jahres_de", "de", "letter", """RheinEnergie – Ihre Jahresabrechnung Strom 2025
Kundennummer 300 418 552, Zählernummer 1ESY1160 4471
Abrechnungszeitraum 01.01.2025 – 31.12.2025
Verbrauch: 1.840 kWh (Vorjahr: 1.910 kWh)
Arbeitspreis 34,12 ct/kWh, Grundpreis 13,90 € pro Monat
Gesamtbetrag brutto 794,50 €, geleistete Abschläge 730,20 €
Nachzahlung: 64,30 €, fällig am 15.02.2026
Ihr neuer monatlicher Abschlag ab März beträgt 67,00 €. Die Nachzahlung buchen wir per SEPA-Lastschrift ab."""),
("strom_anbieter_de", "de", "mail", """Betreff: Willkommen bei Naturstrom Rhein – Ihr Lieferbeginn
Hallo Herr Becker,
vielen Dank für Ihren Wechsel zu uns. Wir beliefern Ihre Wohnung ab dem 1. März mit 100 % Ökostrom. Die Kündigung bei Ihrem bisherigen Versorger haben wir für Sie übernommen. Bitte lesen Sie am Tag des Lieferbeginns Ihren Zählerstand ab und tragen Sie ihn im Kundenportal ein. Ihr Abschlag beträgt 59,00 € im Monat, die Preisgarantie gilt 24 Monate."""),
("energie_nl", "nl", "mail", """Onderwerp: Je jaarnota energie staat klaar
Hoi Jonas,
Je jaarnota voor stroom en gas over de periode januari – december is klaar. Je verbruikte 1.620 kWh stroom en 410 m³ gas. Je hebt in totaal € 1.243 aan termijnbedragen betaald en je werkelijke kosten waren € 1.156. Je krijgt dus € 87 terug; dat bedrag staat binnen tien dagen op je rekening. Je nieuwe maandbedrag wordt € 96.
Groeten, Eneco"""),
("w_flatmate_bills", "nl", "whatsapp", """[WhatsApp – Huis Biltstraat] Daan: De energierekening is binnen, we krijgen €87 terug! Ik heb het al verdeeld, dat is €29 per persoon, ik maak het vanavond naar jullie over.
Sanne: Top! En het nieuwe voorschot?
Daan: €96 per maand, dus €32 elk. Ik pas de vaste opdracht aan."""),
("nebenkosten_de", "de", "letter", """Betriebskostenabrechnung 2025 – Venloer Str. 212, Wohnung 3. OG links
Heizkosten (Verbrauch laut Ista-Ablesung): 486,20 €
Kalt- und Abwasser: 212,40 €
Müllabfuhr und Straßenreinigung: 98,10 €
Hausmeister und Treppenhausreinigung: 141,00 €
Grundsteuer und Gebäudeversicherung: 167,30 €
Summe 1.105,00 €, Ihre Vorauszahlungen 1.080,00 €
Nachforderung 25,00 €. Belege können nach Absprache eingesehen werden."""),
("internet_rechnung_de", "de", "mail", """Betreff: Ihre Vodafone Rechnung für Oktober
Guten Tag Jonas Becker,
Ihre aktuelle Rechnung für Ihren Kabel-Internet-Anschluss liegt im MeinVodafone-Portal bereit. Rechnungsbetrag: 39,99 € für GigaZuhause 250 Kabel. Der Betrag wird am 12. des Monats von Ihrem Konto abgebucht. Tipp: Mit dem Upgrade auf 500 Mbit/s surfen Sie doppelt so schnell – jetzt für nur 5 € mehr im Monat."""),
("meeting_mail_en", "en", "mail", """Subject: Team meeting Thursday 3pm – agenda
Hi all,
quick reminder that our team meeting is on Thursday at 3pm in the large room on the second floor (and on Teams for the remote folks). Agenda: 1) Q3 roadmap and what slipped, 2) budget review for the analytics project, 3) office move in January, 4) any other business. Please add your updates to the shared doc by Wednesday evening so we can keep it to 45 minutes.
Thanks, Miriam"""),

# ---------------------------------------------------------------- parcels
("dhl_de", "de", "mail", """Betreff: Ihr DHL Paket kommt heute
Hallo Jonas Becker,
Ihr Paket von Thalia wird heute zwischen 10:00 und 13:00 Uhr zugestellt. Sendungsnummer 00340434161094042557. Sie haben als Ablageort 'Garage' gewählt; unser Zusteller legt die Sendung dort ab, falls Sie nicht zu Hause sind. Sie können den Liefertag oder Ablageort noch bis 8:00 Uhr in der Post & DHL App ändern."""),
("postnl_nl", "nl", "mail", """Onderwerp: Je pakket is bezorgd
Hoi Jonas,
Je pakket van Coolblue is vandaag om 14:12 bezorgd. Je was niet thuis, daarom hebben we het afgegeven bij je buren op nummer 86. Op de kaart in je brievenbus staat hun naam. Was je pakket er niet? Neem dan binnen 3 dagen contact met ons op via de PostNL app.
Groet, PostNL"""),
("amazon_en", "en", "mail", """Subject: Your Amazon.nl order has shipped
Hello Jonas,
Good news: your order #403-2281715-7713926 is on its way. Logitech MX Master 3S wireless mouse, qty 1.
Carrier: DPD, tracking number 05212345678901.
Estimated arrival: Thursday 13 November, by 8pm.
You can track your package or change the delivery address in Your Orders."""),
("dpd_missed_de", "de", "mail", """Betreff: Wir haben Sie leider nicht angetroffen
Hallo,
unser Fahrer konnte Ihre Sendung 01906 2004 4485 heute leider nicht zustellen. Sie liegt ab morgen 12 Uhr im DPD Pickup Paketshop 'Kiosk am Stadtgarten', Venloer Str. 40, zur Abholung bereit. Bitte bringen Sie einen Ausweis und die Sendungsnummer mit. Die Sendung wird sieben Werktage aufbewahrt und danach an den Absender zurückgeschickt."""),
("w_paket_oma", "de", "whatsapp", """[WhatsApp – Mama] Hast du das Päckchen von Oma bekommen? Sie hat es letzten Montag bei der Post aufgegeben, mit den Plätzchen und dem Schal.
[Jonas] Noch nicht, ich schau mal in die Sendungsverfolgung, hast du die Nummer?
[Mama] Ich frag sie, sie hat den Zettel bestimmt noch."""),
("retour_nl", "nl", "mail", """Onderwerp: We hebben je retour ontvangen
Hoi Jonas,
Je retourzending van de hardloopschoenen (bestelnummer 1042 7788) is in goede orde bij ons magazijn aangekomen. We storten € 89,95 binnen drie werkdagen terug op de rekening waarmee je hebt betaald. Je hoeft hier verder niets voor te doen.
Bedankt voor het winkelen bij bol"""),
("pizza_note", "en", "note", """Pizza dough (Neapolitan-ish, 4 pizzas)
500 g tipo 00 flour, 325 ml cold water, 10 g salt, 1.5 g dried yeast.
Dissolve the yeast in the water, add flour, knead 10 minutes, then salt. Bulk rise 2 hours at room temperature, then divide into 4 balls and put them in the fridge for 24-48 hours. Take out 3 hours before baking. Stretch by hand, no rolling pin. Oven at max with the steel on the top shelf; 6-7 minutes. Topping: San Marzano tomatoes, fior di latte, basil after baking."""),

# ---------------------------------------------------------------- university
("course_announce_en", "en", "mail", """Subject: [INFOMDM] Data Mining – first lecture and practical groups
Dear students,
Welcome to Data Mining. The first lecture takes place on Monday 10 November at 9:00 in Ruppert Blauw instead of the room listed in MyTimetable. Please form groups of three for the practical assignments and register your group on Brightspace before Friday. The reading for week 1 is chapters 1 and 2 of the course book. Office hours are Wednesdays 13:00-14:00 in BBG 5.12.
Kind regards, Dr. Pieter Smit"""),
("vorlesung_ausfall_de", "de", "mail", """Betreff: Statistik II – Vorlesung am Donnerstag entfällt
Liebe Studierende,
die Vorlesung Statistik II am Donnerstag, 13. November, muss wegen Krankheit leider ausfallen. Die Übungen finden wie geplant statt. Der Stoff (Kapitel 6, Konfidenzintervalle) wird in der Vorlesung am 20. November nachgeholt; die Folien stelle ich vorab in ILIAS bereit. Bitte nutzen Sie die freie Zeit für das Übungsblatt 5.
Viele Grüße
Prof. Dr. Sabine Krüger"""),
("tentamen_nl", "nl", "mail", """Onderwerp: Tentamenrooster periode 2
Beste student,
Het tentamen Lineaire Algebra vindt plaats op vrijdag 23 januari van 13:30 tot 16:30 in het Educatorium, zaal Gamma. Neem je collegekaart of een geldig identiteitsbewijs mee; zonder legitimatie mag je niet deelnemen. Rekenmachines zijn niet toegestaan. De herkansing is op 10 april. Inschrijven voor het tentamen kan tot 9 januari via Osiris."""),
("c_exam", "nl", "calendar", """Agenda: Tentamen Lineaire Algebra
Vrijdag 23 januari, 13:30 – 16:30
Locatie: Educatorium, zaal Gamma
Notitie: collegekaart meenemen, geen rekenmachine. Hoofdstuk 4 en 5 nog een keer doorlezen."""),
("lecture_notes_gd_en", "en", "pdf", """Lecture 4 – Optimisation: gradient descent
We minimise a differentiable loss L(w) by repeatedly stepping against the gradient: w ← w − η ∇L(w). The learning rate η controls the step size. If η is too large the iterates overshoot and may diverge; if it is too small, convergence is slow. For convex L with Lipschitz-continuous gradient (constant L), a fixed step η ≤ 1/L guarantees convergence at rate O(1/t). Stochastic gradient descent replaces ∇L by the gradient on a mini-batch, which is noisy but much cheaper per step. Momentum averages past gradients to damp oscillations."""),
("skript_bayes_de", "de", "pdf", """Kapitel 3: Bedingte Wahrscheinlichkeit und der Satz von Bayes
Für Ereignisse A und B mit P(B) > 0 gilt P(A|B) = P(A ∩ B) / P(B). Der Satz von Bayes kehrt die Bedingung um: P(A|B) = P(B|A) · P(A) / P(B).
Beispiel: Eine Krankheit tritt bei 1 % der Bevölkerung auf. Ein Test erkennt Erkrankte mit 95 % Sicherheit, liefert aber bei 5 % der Gesunden ein positives Ergebnis. Dann ist die Wahrscheinlichkeit, bei positivem Test tatsächlich krank zu sein, nur etwa 16 %. Die niedrige A-priori-Wahrscheinlichkeit dominiert das Ergebnis."""),
("college_slides_nl", "nl", "pdf", """College 5 – Neurale netwerken: backpropagation
Een neuraal netwerk leert door de gewichten aan te passen zodat de fout op de trainingsdata kleiner wordt. Backpropagation berekent de afgeleide van de fout naar elk gewicht met de kettingregel, laag voor laag van de uitvoer terug naar de invoer. Daarna worden de gewichten bijgewerkt met een kleine stap in de richting die de fout verlaagt. Activatiefuncties zoals ReLU en sigmoid bepalen hoe goed het signaal terugstroomt; bij diepe netwerken kan de gradiënt verdwijnen."""),
("enrollment_en", "en", "mail", """Subject: Course registration for period 3 opens 3 November
Dear student,
Registration for courses in period 3 is open from Monday 3 November 10:00 until Friday 14 November 23:59 via Osiris Student. Courses with limited capacity are allocated by lottery after the registration period; you will hear the result on 20 November. Late registration is only possible for courses with places left and costs an administrative fee. Check the course catalogue for entry requirements before you register.
Student Desk, Faculty of Science"""),
("w_study_group", "nl", "whatsapp", """[WhatsApp – ML studiegroep] Lotte: Wie heeft de slides van college 5? Ik was er niet en ze staan nog niet op Brightspace.
Jonas: Ik stuur ze zo, ik heb ze gedownload vanochtend.
Ahmed: Weet iemand of de deadline van opdracht 2 is verschoven? Ik hoorde iets over volgende week vrijdag.
Lotte: Ja, naar vrijdag 23:59 volgens de docent."""),

# ---------------------------------------------------------------- thesis
("thesis_feedback_en", "en", "mail", """Subject: Feedback on chapter 3
Hi Jonas,
I read your methodology chapter. The structure works, but the justification for using only German and Dutch news sources needs a paragraph of its own, and the evaluation section should state the baseline before the results. Please also move the hyperparameter table to the appendix. Let's discuss the remaining points on Tuesday at 14:00 in my office (BBG 5.07); bring a printed copy with your changes marked.
Best, Anna de Vries"""),
("c_meeting_supervisor", "en", "calendar", """Calendar: Thesis meeting – Anna de Vries
Tuesday 18 November, 14:00 – 14:45
Location: BBG 5.07
Note: bring printed chapter 3 with changes marked; ask about second reader and the date of the green light meeting."""),
("scriptie_deadline_nl", "nl", "mail", """Onderwerp: Deadlines masterscriptie voorjaar 2027
Beste masterstudenten,
De conceptversie van je masterscriptie moet uiterlijk vrijdag 15 mei 2027 worden ingeleverd bij je begeleider en de tweede lezer. De definitieve versie lever je in vóór 26 juni via Osiris Zaak; daarna volgt de presentatie. Wie de deadline niet haalt, schuift door naar de volgende ronde in september. Vraag tijdig een tweede lezer aan bij de scriptiecoördinator.
Met vriendelijke groet, dr. Eva Mulder, scriptiecoördinator"""),
("masterarbeit_anmeldung_de", "de", "letter", """Prüfungsamt der Wirtschafts- und Sozialwissenschaftlichen Fakultät
Bestätigung der Anmeldung Ihrer Masterarbeit
Thema: Mehrsprachige Nachrichtenklassifikation mit kleinen Sprachmodellen
Erstgutachterin: Prof. Dr. Sabine Krüger
Ausgabedatum: 1. Dezember, Abgabetermin: 1. Juni (Bearbeitungszeit sechs Monate)
Die Arbeit ist in zwei gebundenen Exemplaren und als PDF einzureichen. Eine Verlängerung der Bearbeitungszeit ist nur auf begründeten Antrag möglich."""),
("note_thesis_ideas", "en", "note", """Thesis – open questions
- Research question: does a small multilingual model trained on German news transfer to Dutch without labelled Dutch data?
- Dataset: 40k German articles, 5k Dutch for testing only; maybe add Belgian Flemish sources.
- Related work: cross-lingual transfer papers from 2024-2025, check what Anna sent.
- Baselines: TF-IDF + logistic regression, translate-test.
- Ask about compute budget at the faculty cluster."""),

# ---------------------------------------------------------------- train, travel
("ns_ticket_nl", "nl", "mail", """Onderwerp: Je e-ticket voor 12 december
Hoi Jonas,
Bedankt voor je bestelling. Hier is je e-ticket.
Reis: Amsterdam Centraal → Utrecht Centraal
Datum: vrijdag 12 december, enkele reis, 2e klas
Vertrek 08:14 van spoor 5b, aankomst 08:41
Het ticket is alleen geldig op de reisdatum. Laat de QR-code zien bij de poortjes of aan de conducteur.
Goede reis, NS"""),
("db_ticket_de", "de", "pdf", """DB Online-Ticket – Zugbindung
Hinfahrt am 20.12.2026
Köln Hbf → Utrecht Centraal
ICE 120, Abfahrt 14:47 Gleis 4, Ankunft 17:26
Wagen 7, Platz 45, Großraum, Fenster
Flexpreis Europa, 2. Klasse, 1 Erwachsener, BahnCard 25
Das Ticket gilt nur in Verbindung mit einem amtlichen Lichtbildausweis. Bei Verspätung über 20 Minuten ist die Zugbindung aufgehoben."""),
("c_train_utrecht", "de", "calendar", """Kalender: Zug nach Utrecht
Samstag 20. Dezember, 14:47 – 17:26
Köln Hbf, Gleis 4 → Utrecht Centraal (ICE 120, Wagen 7 Platz 45)
Notiz: Geschenke für die WG nicht vergessen, Ticket ist in der DB-App."""),
("flight_en", "en", "mail", """Subject: Booking confirmation – Amsterdam to Lisbon
Dear Mr Becker,
Thank you for booking with KLM. Booking code: QX7L2P.
Outbound: KL1693, Thursday 9 April, Amsterdam Schiphol 07:05 – Lisbon 09:00
Return: KL1696, Monday 13 April, Lisbon 15:40 – Amsterdam 19:25
Baggage: 1 piece of hand baggage up to 12 kg. Online check-in opens 30 hours before departure."""),
("bahncard_de", "de", "mail", """Betreff: Ihre BahnCard 25 wird verlängert
Hallo Herr Becker,
Ihre BahnCard 25 (2. Klasse) läuft am 31. Januar ab und verlängert sich automatisch um ein weiteres Jahr zum Preis von 62,90 €, sofern Sie nicht bis sechs Wochen vor Ablauf kündigen. Die neue digitale BahnCard finden Sie rechtzeitig in Ihrer DB Navigator App. Als Student können Sie stattdessen die günstigere My BahnCard 25 wählen."""),
("db_delay_de", "de", "mail", """Betreff: Fahrgastrechte – Ihr Antrag auf Entschädigung
Guten Tag,
vielen Dank für Ihren Antrag auf Fahrpreisentschädigung für Ihre Fahrt am 3. Oktober von Köln Hbf nach Utrecht Centraal. Ihr Zug erreichte das Ziel mit 74 Minuten Verspätung. Ihnen stehen daher 25 % des Fahrpreises zu. Wir überweisen 14,75 € innerhalb von zwei Wochen auf Ihr Konto.
Ihr Servicecenter Fahrgastrechte"""),
("w_mum_birthday", "de", "whatsapp", """[WhatsApp – Mama] Denk dran, Samstag ist Omas Achtzigster! Papa holt dich um halb eins am Bahnhof Köln-Süd ab. Bringst du die Fotos mit, die du ausgedruckt hast?
[Jonas] Ja klar, und ich hab noch einen Gutschein für die Therme besorgt.
[Mama] Perfekt, sie wird sich freuen."""),

# ---------------------------------------------------------------- doctor, health
("arzt_termin_de", "de", "mail", """Betreff: Terminbestätigung Praxis Dr. Weber
Sehr geehrter Herr Becker,
hiermit bestätigen wir Ihren Termin in unserer hausärztlichen Praxis am Dienstag, 16. Dezember, um 10:30 Uhr bei Dr. Weber (Check-up und Impfberatung). Bitte bringen Sie Ihre Versichertenkarte und Ihren Impfpass mit und kommen Sie nüchtern, da Blut abgenommen wird. Falls Sie den Termin nicht wahrnehmen können, sagen Sie bitte mindestens 24 Stunden vorher ab.
Ihr Praxisteam Dr. Weber, Allgemeinmedizin"""),
("c_arzt", "de", "calendar", """Kalender: Hausarzt Dr. Weber
Dienstag 16. Dezember, 10:30 – 11:15
Ort: Praxis Dr. Weber, Subbelrather Str. 15, Köln
Notiz: nüchtern kommen, Versichertenkarte und Impfpass mitnehmen."""),
("huisarts_nl", "nl", "mail", """Onderwerp: Bevestiging afspraak huisartsenpraktijk Lombok
Beste Jonas Becker,
Je afspraak bij dokter Bakker is bevestigd voor donderdag 27 november om 09:20. Een gewoon consult duurt tien minuten; heb je meerdere klachten, meld dat dan bij de assistente zodat er een dubbel consult wordt ingepland. Neem je identiteitsbewijs en je zorgpas mee. Afzeggen kan tot 24 uur van tevoren via het patiëntenportaal."""),
("tandarts_nl", "nl", "calendar", """Agenda: Tandarts – halfjaarlijkse controle
Woensdag 3 december, 09:00 – 09:30
Tandartspraktijk Oudegracht, Oudegracht 211
Notitie: ook gebitsreiniging bij de mondhygiënist direct daarna."""),
("krankenkasse_de", "de", "letter", """Techniker Krankenkasse – Ihre Versicherung während des Studiums im Ausland
Sehr geehrter Herr Becker,
da Sie Ihren Wohnsitz in die Niederlande verlegt haben, prüfen wir derzeit, ob Sie weiterhin bei uns versichert bleiben können. Bitte senden Sie uns eine Immatrikulationsbescheinigung der Universität Utrecht und Ihren Arbeitsvertrag als Werkstudent. Ihre Europäische Krankenversicherungskarte (EHIC) bleibt bis zur Klärung gültig."""),

# ---------------------------------------------------------------- newsletters, spam
("newsletter_tech_en", "en", "mail", """Subject: Python Weekly – Issue 712
This week: a deep dive into the new free-threaded interpreter and what it means for C extensions; a practical guide to typing with Protocols; benchmarking polars against pandas on a 50 GB dataset; and five lesser-known features of pytest. Plus: a new release of uv with workspace support, interviews with core developers, and jobs at companies using Python in production. Unsubscribe at any time."""),
("spam_prize_en", "en", "mail", """Subject: Congratulations!!! You have been selected
Dear Customer, you have been randomly selected as the winner of a brand new iPhone 17 Pro in our annual loyalty draw. To claim your prize, simply confirm your shipping details and pay the handling fee of €1.95 within 24 hours. Click here to claim now. If you do not respond, your prize will be given to another participant. This offer is valid today only."""),
("phishing_de", "de", "mail", """Betreff: Wichtig: Ihr Konto wurde vorübergehend gesperrt
Sehr geehrter Kunde,
aufgrund ungewöhnlicher Aktivitäten haben wir Ihr Sparkassen-Konto vorübergehend eingeschränkt. Um eine dauerhafte Sperrung zu vermeiden, bestätigen Sie bitte innerhalb von 48 Stunden Ihre Identität über den folgenden Link und geben Sie Ihre Zugangsdaten sowie die TAN ein. Ihre Sicherheit ist uns wichtig.
Ihr Kundenservice"""),
("newsletter_nl", "nl", "mail", """Onderwerp: Black Friday: tot 50% korting op alles voor je huis!
Alleen dit weekend: kortingen op dekbedden, pannen, lampen en meer. Gratis bezorging vanaf € 20 en als lid van de klantenpas krijg je er nog eens 10% bovenop. Kom langs in de winkel of bestel online. Op = op! Wil je deze mails niet meer ontvangen? Meld je hier af."""),
("newsletter_de", "de", "mail", """Betreff: Stadtbibliothek Köln – Veranstaltungen im November
Liebe Leserinnen und Leser,
im November erwarten Sie Lesungen mit Kölner Autorinnen, ein Workshop zum 3D-Druck im MakerSpace und unser Bücherflohmarkt am 22. November. Neu im Bestand: über 300 E-Books zu Studium und Beruf. Die Zentralbibliothek ist während der Renovierung des Foyers über den Seiteneingang erreichbar. Wir freuen uns auf Ihren Besuch!"""),

# ---------------------------------------------------------------- invoices
("invoice_laptop_en", "en", "pdf", """INVOICE No. 2025-1187
Date: 4 March 2025
Bill to: Jonas Becker, Biltstraat 88, 3572 BJ Utrecht
1 x Lenovo ThinkPad T14 Gen 5, 32 GB RAM, 1 TB SSD – € 1,321.49
1 x USB-C docking station – € 179.00
Subtotal € 1,500.49, VAT 21 % € 315.10, Total € 1,815.59
Paid by iDEAL on 4 March 2025. Warranty: 3 years on-site.
Thank you for your purchase."""),
("rechnung_sanitaer_de", "de", "pdf", """Sanitär Müller GmbH – Rechnung Nr. 25-0388
Leistungsort: Venloer Str. 212, 3. OG, Köln
Austausch der defekten Mischbatterie in der Küche einschließlich Eckventilen
Material: Einhebelmischer 89,00 €, 2 Eckventile 24,00 €
Arbeitszeit 1,5 Std. à 58,00 € = 87,00 €, Anfahrt 38,00 €
Nettobetrag 238,00 €, zzgl. 19 % MwSt. 45,22 €, Rechnungsbetrag 283,22 €
Zahlbar innerhalb von 14 Tagen ohne Abzug."""),
("factuur_fiets_nl", "nl", "pdf", """Fietsenmaker De Spaak – Factuur 2025-0412
Klant: J. Becker
Reparatie stadsfiets Gazelle:
nieuwe ketting € 22,50
remblokken voor en achter € 18,00
achterband geplakt € 8,00
arbeidsloon € 16,00
Totaal € 64,50 (incl. 21% btw), voldaan per pin.
Bedankt en veilig fietsen!"""),
("invoice_reminder_de", "de", "mail", """Betreff: Zahlungserinnerung – Rechnung 4471
Sehr geehrter Herr Becker,
sicher haben Sie es nur übersehen: Unsere Rechnung Nr. 4471 vom 2. Oktober über 240,00 € für den Niederländisch-Intensivkurs A2 ist noch offen. Bitte überweisen Sie den Betrag bis zum 20. November. Sollte sich Ihre Zahlung mit diesem Schreiben überschnitten haben, betrachten Sie es bitte als gegenstandslos.
Sprachschule Lingua Köln"""),

# ---------------------------------------------------------------- contracts
("arbeitsvertrag_de", "de", "pdf", """Arbeitsvertrag für Werkstudenten
zwischen der Rheinblick Analytics GmbH, Köln, und Herrn Jonas Becker
§ 2 Arbeitszeit: Die regelmäßige wöchentliche Arbeitszeit beträgt 20 Stunden während der Vorlesungszeit. Die Tätigkeit wird überwiegend im Homeoffice erbracht.
§ 3 Vergütung: Der Stundenlohn beträgt 17,00 € brutto, zahlbar zum Monatsende.
§ 4 Urlaub: Der Urlaubsanspruch beträgt anteilig 12 Arbeitstage im Kalenderjahr.
§ 7 Kündigung: Das Arbeitsverhältnis kann mit einer Frist von vier Wochen gekündigt werden."""),
("mobile_contract_en", "en", "pdf", """SimplyMobile – Terms of your mobile plan
Plan: Unlimited Data 5G, € 20 per month
Minimum term: 24 months from activation (activated 1 June 2025)
After the minimum term, the contract continues month to month and can be cancelled with one month's notice.
Early termination: remaining monthly fees up to the end of the minimum term are due.
Roaming in the EU at no extra cost under fair use rules."""),
("sportschool_nl", "nl", "mail", """Onderwerp: Bevestiging opzegging lidmaatschap
Beste Jonas,
We hebben je opzegging ontvangen. Je lidmaatschap van Basic-Fit Utrecht Vaartsche Rijn eindigt op 31 januari. De laatste incasso van € 29,99 vindt plaats op 1 januari. Tot de einddatum kun je gewoon blijven sporten. We vinden het jammer dat je gaat; misschien tot ziens!
Team Basic-Fit"""),
("nda_en", "en", "pdf", """Confidentiality Agreement
1. The Working Student shall keep confidential all information about clients, data sets and software of Rheinblick Analytics GmbH that becomes known to them during the employment.
2. This obligation continues for three years after the end of the employment.
3. Documents and data carriers must be returned at the end of the employment; copies must be deleted.
4. Publication of results, including in a thesis, requires prior written approval of the company."""),

# ---------------------------------------------------------------- notes
("note_packing", "en", "note", """Lisbon packing list
- passport, ID, KLM boarding pass in the app
- light jacket (evenings windy), sunglasses, sunscreen
- walking shoes, sandals
- charger + EU adapter not needed
- camera, spare battery
- book for the flight
- cash for the tram 28 and the Pastéis de Belém"""),
("note_groceries_de", "de", "note", """Einkaufsliste
Haferflocken, Milch (Hafer), Bananen, Äpfel, Tomaten, Zwiebeln, Knoblauch, Linsen, Reis, Feta, Eier, Brot vom Bäcker, Kaffeebohnen, Spülmittel, Müllbeutel. Für Samstag: Zutaten für Shakshuka und eine Flasche Wein für Daan."""),
("note_reading_nl", "nl", "note", """Leeslijst
- 'Het diner' van Herman Koch (tweedehands bij De Slegte gezien)
- 'Max Havelaar' – eindelijk eens lezen, voor het Nederlands
- 'De avonden' – Lotte zegt dat het saai is maar briljant
- iets van Annie M.G. Schmidt voorlezen als oefening uitspraak"""),
("note_budget_de", "de", "note", """Monatsbudget ab Oktober
Einnahmen: Werkstudent ca. 1.350 € netto
Ausgaben: Miete Zimmer 650 €, Handy 20 €, Lebensmittel 250 €, Fahrtkosten Bahn 60 €, Sport 30 €, Sprachkurs 40 €, Sparen 200 €
Rest für Freizeit ca. 100 €. Ziel: bis Juni 1.500 € Notgroschen."""),

# ---------------------------------------------------------------- calendar, social
("c_birthday_oma", "de", "calendar", """Kalender: Omas 80. Geburtstag
Samstag 29. November, 13:00
Restaurant Zum Treppchen, Köln-Rodenkirchen
Notiz: Fotos und Gutschein Therme mitbringen, Blumen bestellen."""),
("c_climbing", "en", "calendar", """Calendar: Bouldering with Sam
Saturday 15 November, 11:00 – 13:00
Monk Bouldergym Utrecht
Note: bring own shoes and chalk."""),
("w_climbing_en", "en", "whatsapp", """[WhatsApp – Sam] Are we still on for bouldering on Saturday? I can pick you up at 10:30, I've got the car this weekend.
[Jonas] Yes! 10:30 works. Should we try the new blue routes?
[Sam] Definitely, and lunch afterwards at the place by the canal."""),

# ---------------------------------------------------------------- admin
("gemeente_nl", "nl", "mail", """Onderwerp: Bevestiging afspraak inschrijving BRP
Beste heer Becker,
U heeft een afspraak gemaakt om u in te schrijven in de Basisregistratie Personen (BRP) van de gemeente Utrecht. Datum: dinsdag 11 februari, 10:40, Stadskantoor, Stadsplateau 1. Neem uw paspoort of identiteitskaart en uw huurcontract mee. Na de inschrijving ontvangt u uw burgerservicenummer (BSN)."""),
("abmeldung_de", "de", "letter", """Stadt Köln – Bürgeramt Ehrenfeld
Abmeldebestätigung
Herr Jonas Becker hat sich mit Wirkung vom 31. August 2025 von der Anschrift Venloer Str. 212, 50823 Köln abgemeldet. Neue Anschrift: Biltstraat 88, Utrecht, Niederlande (Wegzug ins Ausland). Diese Bestätigung kann bei Behörden, Banken und Versicherungen vorgelegt werden."""),
("library_fine_nl", "nl", "mail", """Onderwerp: Te laat ingeleverde materialen
Beste lener,
De volgende boeken zijn te laat ingeleverd: 'Pattern Recognition and Machine Learning' (3 dagen) en 'Statistiek in de praktijk' (3 dagen). De boete bedraagt € 1,80 en is toegevoegd aan je account. Je kunt pas weer lenen als het openstaande bedrag is betaald via de website of bij de balie.
Universiteitsbibliotheek Utrecht"""),
("job_interview_en", "en", "mail", """Subject: Interview invitation – Data Analyst internship
Dear Jonas,
Thank you for your application for the Data Analyst internship at our Utrecht office. We would like to invite you to a first interview on Wednesday 26 November at 11:00, via video call. The interview will take about 45 minutes and includes a short case discussion. Please confirm whether this time suits you.
Kind regards, Recruitment team, Nordwind Energy"""),
# ---------------------------------------------------------------- calendar entries that are only a title
# (most of a real calendar: "Frisör", "Free time"); the filler has many more of them (testset_filler.short_titles)
("t_zahnarzt", "de", "calendar", "Zahnarzt Kontrolle"),
("t_huisarts", "nl", "calendar", "Huisarts"),
("t_klausur", "de", "calendar", "Klausur Statistik"),
("t_friseur", "de", "calendar", "Friseur"),
("t_essay", "de", "calendar", "Abgabe Essay Ethik"),
]
