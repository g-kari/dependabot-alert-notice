package web

func riskPriorityLabel(priority string) string {
	switch priority {
	case "incident":
		return "インシデント対応"
	case "immediate":
		return "即時対応"
	case "today":
		return "本日中"
	case "next_business_day":
		return "次の営業日"
	case "planned":
		return "計画対応"
	default:
		return "対応期限を確認"
	}
}

func riskStatusLabel(status string) string {
	switch status {
	case "confirmed":
		return "確認済み"
	case "provisional":
		return "暫定（要確認）"
	case "not_affected":
		return "適用外"
	case "mitigated":
		return "緩和済み"
	case "conflict":
		return "情報に矛盾"
	default:
		return "未確認"
	}
}
