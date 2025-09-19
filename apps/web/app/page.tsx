import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, Users, Database, BarChart3 } from 'lucide-react'

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-accent2-50">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary rounded-full mb-6">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Threat Intelligence Platform
          </h1>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Advanced threat intelligence and vulnerability management for modern security teams
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          <Card>
            <CardHeader>
              <Database className="w-8 h-8 text-primary mb-2" />
              <CardTitle>Multi-Source Intelligence</CardTitle>
              <CardDescription>
                Aggregate threat data from NVD, OSV, GitHub, CISA KEV, and custom RSS feeds
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <BarChart3 className="w-8 h-8 text-accent mb-2" />
              <CardTitle>Real-time Analytics</CardTitle>
              <CardDescription>
                Track emerging threats with automated analysis and AI-powered summaries
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Users className="w-8 h-8 text-info mb-2" />
              <CardTitle>Team Collaboration</CardTitle>
              <CardDescription>
                Role-based access control with organization management and user invitations
              </CardDescription>
            </CardHeader>
          </Card>
        </div>

        <div className="text-center">
          <Link href="/signin">
            <Button size="lg" className="bg-primary hover:bg-primary-600 text-white px-8 py-3">
              Get Started
            </Button>
          </Link>
        </div>
      </div>
    </div>
  )
}