import './OnboardingCard.css';

interface OnboardingCardProps {
  icon: string;
  title: string;
  description: string;
  badge: string;
  onClick: () => void;
}

export function OnboardingCard({
  icon,
  title,
  description,
  badge,
  onClick
}: OnboardingCardProps) {
  return (
    <div className="onboarding-card" onClick={onClick}>
      <div className="card-emoji">{icon}</div>
      <div className="card-title">{title}</div>
      <div 
        className="card-desc" 
        dangerouslySetInnerHTML={{ __html: description }}
      />
      <div className="card-badge">{badge}</div>
    </div>
  );
}
