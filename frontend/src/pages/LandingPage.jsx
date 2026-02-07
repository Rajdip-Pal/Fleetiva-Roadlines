import { Link } from "react-router-dom";

export default function LandingPage() {
  return (
    <div className="page">
      <div className="page-content">
        <section className="hero">
          <div className="hero-content">
            <span className="pill">Fleetiva Roadlines</span>
            <h1 className="hero-title">
              Smart freight matching for every shipper, driver, and admin team.
            </h1>
            <p className="hero-subtitle">
              Post loads, match trucks, and keep shipments moving with real-time
              dashboards built for logistics teams.
            </p>
            <div className="hero-actions">
              <Link to="/register" className="btn btn-primary">
                Get Started
              </Link>
              <Link to="/login" className="btn btn-secondary">
                Sign In
              </Link>
            </div>
          </div>
          <div className="hero-grid">
            <div className="card hero-card">
              <h3 className="section-title">Live Load Matching</h3>
              <p className="text-muted">
                Instantly pair posted loads with available trucks and dispatch
                within minutes.
              </p>
            </div>
            <div className="card hero-card">
              <h3 className="section-title">Role-Based Dashboards</h3>
              <p className="text-muted">
                Tailored experiences for customers, drivers, admins, and super
                admins.
              </p>
            </div>
            <div className="card hero-card">
              <h3 className="section-title">Operational Visibility</h3>
              <p className="text-muted">
                Track bookings, payments, and system activity with clear, clean
                reporting.
              </p>
            </div>
          </div>
        </section>

        <section className="card-grid cols-2">
          <div className="card">
            <h3 className="section-title">For Shippers</h3>
            <p className="text-muted">
              Create loads, receive matches, and monitor delivery milestones in
              one place.
            </p>
          </div>
          <div className="card">
            <h3 className="section-title">For Drivers</h3>
            <p className="text-muted">
              Post truck availability, manage assignments, and keep your fleet
              utilized.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}
