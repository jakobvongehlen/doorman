# (query, lang, type, [relevant doc ids]); type: kw = short keywords, same = same language as the target with
# shared words, xl = other language than the target, para = paraphrase sharing no content word with the target,
# q = natural question. The first relevant id is the main target.

DEPOSIT = ["kaution_rueck", "kaution_konto", "borg_nl", "huurcontract_nl", "w_borg_chat"]
ELEC = ["strom_jahres_de", "energie_nl", "w_flatmate_bills"]
PARCEL = ["dhl_de", "postnl_nl", "amazon_en", "dpd_missed_de", "w_paket_oma"]
DOCTOR = ["arzt_termin_de", "huisarts_nl", "c_arzt", "t_huisarts"]
TAXFILE = ["steuer_elster_de", "belasting_nl", "tax_advisor_en"]

QUERIES = [
# rent, deposit
("rent deposit", "en", "xl", DEPOSIT),
("Mietkaution zurück", "de", "kw", ["kaution_rueck", "kaution_konto", "w_borg_chat", "borg_nl", "huurcontract_nl"]),
("borg terugkrijgen", "nl", "kw", ["w_borg_chat", "borg_nl", "huurcontract_nl", "kaution_rueck", "kaution_konto"]),
("when do I get my deposit back from the old landlord", "en", "q", ["kaution_rueck", "w_borg_chat", "kaution_konto"]),
("security deposit for the room in Utrecht", "en", "xl", ["borg_nl", "huurcontract_nl"]),
("Geld vom Vermieter nach dem Auszug", "de", "para", ["kaution_rueck"]),
("notice period for my apartment", "en", "xl", ["mietvertrag_de"]),
("huurverhoging", "nl", "kw", ["huurverhoging_nl", "mieterhoehung_de"]),
("Mieterhöhung", "de", "kw", ["mieterhoehung_de", "huurverhoging_nl"]),
("rent going up next year", "en", "para", ["mieterhoehung_de", "huurverhoging_nl"]),
# tax
("tax refund", "en", "xl", ["steuerbescheid_de"]),
("Steuererklärung abgeben", "de", "kw", TAXFILE),
("belastingaangifte", "nl", "kw", ["belasting_nl", "steuer_elster_de", "tax_advisor_en"]),
("how much money did the tax office pay back", "en", "q", ["steuerbescheid_de"]),
("Einspruch gegen den Steuerbescheid Frist", "de", "same", ["steuerbescheid_de"]),
("income tax deadline in the Netherlands", "en", "xl", ["belasting_nl", "tax_advisor_en"]),
("zorgtoeslag", "nl", "kw", ["toeslag_nl"]),
("monthly government contribution to health insurance costs", "en", "para", ["toeslag_nl"]),
# electricity, utilities
("electricity bill", "en", "xl", ELEC),
("Stromrechnung", "de", "kw", ELEC),
("energierekening", "nl", "kw", ["energie_nl", "w_flatmate_bills", "strom_jahres_de"]),
("how much power did I use last year", "en", "q", ["strom_jahres_de", "energie_nl"]),
("neuer Stromanbieter Ökostrom", "de", "same", ["strom_anbieter_de"]),
("statement of heating and water costs for the flat", "en", "xl", ["nebenkosten_de"]),
# parcels
("package delivery", "en", "xl", PARCEL),
("pakket bezorgd", "nl", "kw", ["postnl_nl", "dhl_de", "amazon_en", "dpd_missed_de", "w_paket_oma"]),
("Paket im Paketshop abholen", "de", "same", ["dpd_missed_de"]),
("where did the courier leave my parcel", "en", "q", ["postnl_nl", "dhl_de"]),
("Päckchen von Oma", "de", "same", ["w_paket_oma"]),
("refund for returned shoes", "en", "xl", ["retour_nl"]),
("pizza dough recipe", "en", "same", ["pizza_note"]),
# university
("lecture cancelled", "en", "xl", ["vorlesung_ausfall_de"]),
("wanneer is het tentamen lineaire algebra", "nl", "q", ["tentamen_nl", "c_exam"]),
("exam date linear algebra", "en", "xl", ["tentamen_nl", "c_exam"]),
("Klausurtermin", "de", "kw", ["tentamen_nl", "c_exam", "t_klausur"]),
("gradient descent learning rate", "en", "same", ["lecture_notes_gd_en"]),
("bedingte Wahrscheinlichkeit", "de", "same", ["skript_bayes_de"]),
("Bayes theorem example", "en", "xl", ["skript_bayes_de"]),
("backpropagation uitleg", "nl", "same", ["college_slides_nl"]),
("how do neural networks learn their weights", "en", "q", ["college_slides_nl", "lecture_notes_gd_en"]),
("Anmeldung für Kurse im nächsten Block", "de", "xl", ["enrollment_en"]),
("slides van college 5", "nl", "same", ["w_study_group", "college_slides_nl"]),
# thesis
("feedback on my thesis chapter", "en", "same", ["thesis_feedback_en", "c_meeting_supervisor"]),
("Treffen mit der Betreuerin der Masterarbeit", "de", "xl", ["c_meeting_supervisor", "thesis_feedback_en"]),
("inleverdatum scriptie", "nl", "same", ["scriptie_deadline_nl"]),
("thesis draft deadline", "en", "xl", ["scriptie_deadline_nl", "masterarbeit_anmeldung_de"]),
("Masterarbeit anmelden", "de", "same", ["masterarbeit_anmeldung_de"]),
("research question ideas", "en", "same", ["note_thesis_ideas"]),
# train, travel
("when does my train to Utrecht leave", "en", "q", ["db_ticket_de", "c_train_utrecht", "ns_ticket_nl"]),
("treinkaartje Amsterdam Utrecht", "nl", "same", ["ns_ticket_nl"]),
("Zugticket", "de", "kw", ["db_ticket_de", "ns_ticket_nl", "c_train_utrecht"]),
("Entschädigung Zugverspätung", "de", "same", ["db_delay_de"]),
("money back because the train was late", "en", "para", ["db_delay_de"]),
("vlucht naar Lissabon", "nl", "xl", ["flight_en"]),
# doctor
("doctor's appointment", "en", "xl", DOCTOR),
("Arzttermin", "de", "kw", ["arzt_termin_de", "c_arzt", "huisarts_nl", "t_huisarts"]),
("afspraak huisarts", "nl", "kw", ["huisarts_nl", "t_huisarts", "arzt_termin_de", "c_arzt"]),
("dentist checkup", "en", "xl", ["tandarts_nl", "t_zahnarzt"]),
("Zahnarzt", "de", "kw", ["tandarts_nl", "t_zahnarzt"]),
# calendar entries that are only a title
("haircut", "en", "xl", ["t_friseur"]),
("kapper", "nl", "xl", ["t_friseur"]),
("statistics exam", "en", "xl", ["t_klausur"]),
("when is the ethics essay due", "en", "q", ["t_essay"]),
# contracts, invoices, misc
("cancel gym membership", "en", "xl", ["sportschool_nl"]),
("Kündigungsfrist Handyvertrag", "de", "xl", ["mobile_contract_en"]),
("hourly wage in my student job contract", "en", "xl", ["arbeitsvertrag_de"]),
("factuur laptop", "nl", "xl", ["invoice_laptop_en"]),
("Rechnung Fahrradreparatur", "de", "xl", ["factuur_fiets_nl"]),
("who fixed the kitchen tap", "en", "para", ["rechnung_sanitaer_de"]),
("phishing", "en", "kw", ["phishing_de", "spam_prize_en"]),
("register my address at the city hall", "en", "xl", ["gemeente_nl", "abmeldung_de"]),
("library fine for overdue books", "en", "xl", ["library_fine_nl"]),
("bouldering Saturday", "en", "same", ["w_climbing_en", "c_climbing"]),
("Omas Geburtstag", "de", "same", ["c_birthday_oma", "w_mum_birthday"]),
("grandma's birthday party", "en", "xl", ["c_birthday_oma", "w_mum_birthday"]),
("packing list Lisbon", "en", "same", ["note_packing"]),
# more paraphrases and questions
("money I paid upfront when moving into the room", "en", "para", ["borg_nl", "huurcontract_nl"]),
("message where a stranger wants my online banking login", "en", "para", ["phishing_de"]),
("Mitteilung, dass die Uni-Veranstaltung nicht stattfindet", "de", "para", ["vorlesung_ausfall_de"]),
("bonnetje van mijn nieuwe computer", "nl", "para", ["invoice_laptop_en"]),
("wat kost mijn telefoonabonnement per maand", "nl", "q", ["mobile_contract_en"]),
("wie viele Urlaubstage habe ich als Werkstudent", "de", "q", ["arbeitsvertrag_de"]),
("wann muss ich die Masterarbeit abgeben", "de", "q", ["masterarbeit_anmeldung_de", "scriptie_deadline_nl"]),
("what do I need to bring to the city registration appointment", "en", "q", ["gemeente_nl"]),
]

# Nothing in the corpus is about these (the closest are near misses: health insurance, a gym, an internship).
NONSENSE = [
    "xylophone dinosaur",
    "car insurance",
    "volcano eruption Iceland",
    "chess opening theory",
    "Kubernetes cluster upgrade",
    "wedding dress fitting",
    "aquarium vissen voeren",
    "Formel 1 Rennergebnisse",
    "knitting pattern for a sweater",
    "Hochzeitstorte bestellen",
    "submarine sonar",
    "quantum entanglement experiment",
]
